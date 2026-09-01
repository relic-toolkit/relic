/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of an efficiently decodable verifiable delay function over
 * class groups.
 *
 * The evaluation of the input x is the triple
 *
 *     u = g*y,  y = g^(2^t),  z = psi_q(pi) * F^(l^-1 x mod q),
 *
 * where g is the oracle image of x, l is a prime derived from (u, y), and pi is
 * the Wesolowski witness for y = g^(2^t). Decoding recovers x from
 *
 *     W = z^l * psi_q(u)^r * psi_q(y)^-(r+1) = F^x,   r = 2^t mod l,
 *
 * by a discrete logarithm in the kernel, and then checks g = u*y^-1 against the
 * oracle, which binds the triple to its input. Producing the triple costs t
 * sequential squarings; decoding it costs poly(log t).
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/** Domain separation for the two oracles. */
#define CLVDF_TAG_G		((uint8_t)0x0)
#define CLVDF_TAG_P		((uint8_t)0x1)

/** Largest number of stored powers the witness assembly will allocate. */
#define CLVDF_MAX_CHK	(1 << 16)

/** Largest window it will use, beyond which the descent outgrows the saving. */
#define CLVDF_MAX_WIN	24

/** Size in bits of the challenge primes, twice the security level. */
#define CLVDF_CHAL_BITS	256

/**
 * Hashes a tag, the delay, the discriminant and a payload into a digest, so
 * that both oracles are separated and every value is bound to the instance.
 */
static void clvdf_absorb(uint8_t *h, uint8_t tag, size_t t, const uint8_t *in,
		size_t len) {
	size_t n = 0, dl = bn_size_bin(&(core_get()->qf_dk));
	uint8_t *buf = RLC_ALLOCA(uint8_t, 1 + sizeof(size_t) + dl + len);

	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	buf[n++] = tag;
	memcpy(buf + n, &t, sizeof(size_t));
	n += sizeof(size_t);
	bn_write_bin(buf + n, dl, &(core_get()->qf_dk));
	n += dl;
	if (len > 0) {
		memcpy(buf + n, in, len);
		n += len;
	}
	md_map(h, buf, n);
	RLC_FREE(buf);
}

/**
 * Maps an input to a (squared) element of the source group.
 *
 * The result is squared, which places it in the subgroup of squares where the
 * sequentiality assumption is stated.
 */
static void clvdf_map_g(qf_t g, size_t t, const bn_t x) {
	ctx_t *ctx = core_get();
	size_t n = 0, dl = bn_size_bin(&(core_get()->qf_dk));
	size_t xl = bn_size_bin(x);
	uint8_t *in = RLC_ALLOCA(uint8_t, 1 + sizeof(size_t) + dl + xl);

	if (in == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	RLC_TRY {
		in[n++] = CLVDF_TAG_G;
		memcpy(in + n, &t, sizeof(size_t));
		n += sizeof(size_t);
		bn_write_bin(in + n, dl, &(ctx->qf_dk));
		n += dl;
		bn_write_bin(in + n, xl, x);
		n += xl;

		qf_map(g, in, n, &(ctx->qf_dk), bn_bits(&(ctx->qf_dk)) / 2);
		qf_dup(g, g, &(ctx->qf_bk));
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		RLC_FREE(in);
	}
}

/**
 * Maps a transcript to a prime challenge. The conductor is excluded so that the
 * challenge stays invertible modulo the plaintext prime.
 */
static void clvdf_map_p(bn_t l, size_t t, const qf_t u, const qf_t y) {
	uint8_t h[RLC_MD_LEN];
	size_t n = 0;
	size_t la = bn_size_bin(u->a), lb = bn_size_bin(u->b);
	size_t lc = bn_size_bin(y->a), ld = bn_size_bin(y->b);
	uint8_t *bin = RLC_ALLOCA(uint8_t, la + lb + lc + ld);

	if (bin == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	bn_write_bin(bin + n, la, u->a); n += la;
	bn_write_bin(bin + n, lb, u->b); n += lb;
	bn_write_bin(bin + n, lc, y->a); n += lc;
	bn_write_bin(bin + n, ld, y->b); n += ld;
	clvdf_absorb(h, CLVDF_TAG_P, t, bin, n);

	bn_read_bin(l, h, RLC_MIN(sizeof(h), CLVDF_CHAL_BITS / 8));
	bn_set_bit(l, 0, 1);
	bn_set_bit(l, CLVDF_CHAL_BITS - 1, 1);
	while (!bn_is_prime(l) || bn_cmp(l, &(core_get()->qf_q)) == RLC_EQ) {
		bn_next_prime(l, l);
	}
	
	RLC_FREE(bin);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_clvdf_set(qf_t f, const bn_t q, size_t disc_bits) {
	bn_t t;
	int result = RLC_OK;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		/*
		 * Sampling a discriminant can fail, so return error instead of raising
		 * an exception.
		 */
		if (qf_group_set_cond(q, disc_bits) != RLC_OK) {
			result = RLC_ERR;
		} else {
			/* F generates the kernel of the projection and has order q */
			bn_sqr(t, &(core_get()->qf_q));
			qf_set_dsc(f, t, &(core_get()->qf_q), &(core_get()->qf_d));
			if (!qf_has_dsc(f, &(core_get()->qf_d))) {
				result = RLC_ERR;
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(t);
	}
	return result;
}

void cp_clvdf_evl(qf_t u, qf_t z, qf_t y, const qf_t f, size_t t,
		const bn_t x) {
	qf_t g, pi, wf, run;
	qf_t *tab = NULL, *acc = NULL;
	bn_t l, e, m;
	uint32_t *dig = NULL;
	size_t best = 0, w, wi, sc, nc, nd = 0;

	qf_null(g);
	qf_null(pi);
	qf_null(wf);
	qf_null(run);
	bn_null(l);
	bn_null(e);
	bn_null(m);

	RLC_TRY {
		qf_new(g);
		qf_new(pi);
		qf_new(wf);
		qf_new(run);
		bn_new(l);
		bn_new(e);
		bn_new(m);

		clvdf_map_g(g, t, x);

		/*
		 * The delay is the t squarings below and nothing else. Every w-th power
		 * of the base is kept as it goes past, so that the witness can be
		 * assembled from those afterwards instead of by replaying the chain,
		 * which would double the sequential work for no extra delay.
		 *
		 * The window is chosen to minimise the memory cost, which costs one
		 * composition per stored power and two per window value, so about
		 * t/w + 2^(w + 1). Both constraints pull against each other:
		 * a wider window stores fewer powers but makes the descent over
		 * the window values longer, and it is the storage that binds first,
		 * since it is t over w forms of a few kilobytes each.
		 *
		 * When no window keeps the storage inside the budget, the witness is
		 * replayed instead. That costs a second pass over the chain, so twice
		 * the sequential work, but it needs no storage at all. For a delay
		 * large enough to matter that is the only option: holding t over w
		 * forms with w capped is hundreds of gigabytes, and raising w past the
		 * cap makes the descent longer than the chain it replaces.
		 */
		w = 0;
		for (wi = 2; wi <= CLVDF_MAX_WIN; wi++) {
			size_t chk = (t + wi - 1) / wi + 1;
			size_t cost;

			if (chk > CLVDF_MAX_CHK) {
				continue;
			}
			cost = chk + ((size_t)2 << wi);
			if (w == 0 || cost < best) {
				w = wi;
				best = cost;
			}
		}

		if (w == 0) {
			/* no window fits the budget, so the chain is replayed */
			/* cost of 2t duplications and ~t/2 compositions*/
			qf_copy(y, g);
			for (size_t i = 0; i < t; i++) {
				qf_dup(y, y, &(core_get()->qf_bk));
			}
			qf_com(u, g, y, 0, &(core_get()->qf_bk));

			clvdf_map_p(l, t, u, y);

			qf_set_one(pi, &(core_get()->qf_dk));
			bn_set_dig(e, 1);
			for (size_t i = 0; i < t; i++) {
				bn_dbl(e, e);
				if (bn_cmp(e, l) != RLC_LT) {
					bn_sub(e, e, l);
					qf_dup(pi, pi, &(core_get()->qf_bk));
					qf_com(pi, pi, g, 0, &(core_get()->qf_bk));
				} else {
					qf_dup(pi, pi, &(core_get()->qf_bk));
				}
			}
		} else {
			sc = (t + w - 1) / w + 1;

			/* Allocate from the heap, otherwise no space. */
			tab = (qf_t *)calloc(sc, sizeof(qf_t));
			if (tab == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			for (size_t i = 0; i < sc; i++) {
				qf_null(tab[i]);
				qf_new(tab[i]);
			}

			qf_copy(y, g);
			qf_copy(tab[0], g);
			nc = 1;
			for (size_t i = 0; i < t; i++) {
				qf_dup(y, y, &(core_get()->qf_bk));
				if (((i + 1) % w) == 0 && nc < sc) {
					qf_copy(tab[nc++], y);
				}
			}
			qf_com(u, g, y, 0, &(core_get()->qf_bk));

			clvdf_map_p(l, t, u, y);

			/*
			* The witness is g raised to floor(2^t / l). Writing that quotient in
			* base two to the w, the witness is the product of the stored powers
			* each raised to its own digit, since the stored powers are exactly the
			* base raised to those places. Grouping the digits by value turns the
			* product into one composition per stored power plus a short pass over
			* the possible digits, so the whole thing costs about t over w plus two
			* to the w rather than t.
			*/
			dig = (uint32_t *)calloc(nc, sizeof(uint32_t));
			if (dig == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			bn_zero(e);
			for (size_t i = t + 1; i-- > 0; ) {
				bn_dbl(e, e);
				if (i == t) {
					bn_add_dig(e, e, 1);	/* the only set bit of two to the t */
				}
				if (bn_cmp(e, l) != RLC_LT) {
					bn_sub(e, e, l);
					if (i / w < nc) {
						dig[i / w] |= (uint32_t)1 << (i % w);
					}
				}
			}

			nd = (size_t)1 << w;
			acc = (qf_t *)calloc(nd, sizeof(qf_t));
			if (acc == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			for (size_t i = 0; i < nd; i++) {
				qf_null(acc[i]);
				qf_new(acc[i]);
				qf_set_one(acc[i], &(core_get()->qf_dk));
			}

			/* gather the stored powers by the digit that multiplies them */
			for (size_t i = 0; i < nc; i++) {
				size_t v = (size_t)dig[i];

				if (v > 0) {
					qf_com(acc[v], acc[v], tab[i], 0, &(core_get()->qf_bk));
				}
			}

			/*
			* With the groups formed, the witness follows from a descent over
			* digit values: each step squares what is held and folds in the
			* group for the next value down.
			*/
			qf_set_one(pi, &(core_get()->qf_dk));
			qf_set_one(run, &(core_get()->qf_dk));
			for (size_t i = nd; i-- > 1; ) {
				qf_com(run, run, acc[i], 0, &(core_get()->qf_bk));
				qf_com(pi, pi, run, 0, &(core_get()->qf_bk));
			}
		}

		/* z = psi_q(pi) * F^(l^-1 x mod q) */
		qf_psi(z, pi, &(core_get()->qf_d), &(core_get()->qf_b));
		bn_mod(m, x, &(core_get()->qf_q));
		bn_mod_inv(e, l, &(core_get()->qf_q));
		bn_mul(m, m, e);
		bn_mod(m, m, &(core_get()->qf_q));
		if (!bn_is_zero(m)) {
			qf_exp(wf, f, m, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_com(z, z, wf, 0, &(core_get()->qf_b));
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		if (tab != NULL) {
			for (size_t i = 0; i < sc; i++) {
				qf_free(tab[i]);
			}
			free(tab);
		}
		if (acc != NULL) {
			for (size_t i = 0; i < nd; i++) {
				qf_free(acc[i]);
			}
			free(acc);
		}
		free(dig);
		qf_free(g);
		qf_free(pi);
		qf_free(wf);
		qf_free(run);
		bn_free(l);
		bn_free(e);
		bn_free(m);
	}
}

int cp_clvdf_dec(bn_t x, size_t t, const qf_t u, const qf_t z, const qf_t y) {
	qf_t w, s, g, h;
	bn_t l, r, e, two;
	int result = 0;

	qf_null(w);
	qf_null(s);
	qf_null(g);
	qf_null(h);
	bn_null(l);
	bn_null(r);
	bn_null(e);
	bn_null(two);

	RLC_TRY {
		qf_new(w);
		qf_new(s);
		qf_new(g);
		qf_new(h);
		bn_new(l);
		bn_new(r);
		bn_new(e);
		bn_new(two);

		if (qf_has_dsc(u, &(core_get()->qf_dk)) &&
				qf_has_dsc(y, &(core_get()->qf_dk)) &&
				qf_has_dsc(z, &(core_get()->qf_d))) {
			clvdf_map_p(l, t, u, y);

			/* r = 2^t mod l, by exponentiation on delay rather than on 2^t */
			bn_set_dig(two, 2);
			bn_set_dig(r, t);
			bn_mxp(r, two, r, l);

			/*
			* W = z^l * psi_q(u)^r * psi_q(y)^-(r+1).
			*/
			qf_exp(w, z, l, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_psi(s, u, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_exp(s, s, r, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_com(w, w, s, 0, &(core_get()->qf_b));
			bn_add_dig(e, r, 1);
			qf_psi(s, y, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_exp(s, s, e, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_com(w, w, s, 1, &(core_get()->qf_b));

			/* the result must lie in the kernel, where the logarithm is easy */
			qf_phi(s, w, 1);
			if (qf_is_one(s)) {
				qf_kern(x, w);

				/*
				* g = u*y^-1 has to be the oracle image. That check binds the
				* triple to the input, and it also settles the sign: the kernel
				* logarithm comes back only up to the sign of the class.
				*/
				qf_neg(h, y);
				qf_com(g, u, h, 0, &(core_get()->qf_bk));
				clvdf_map_g(h, t, x);
				if (qf_cmp(g, h) != RLC_EQ) {
					bn_sub(x, &(core_get()->qf_q), x);
					bn_mod(x, x, &(core_get()->qf_q));
					clvdf_map_g(h, t, x);
					result = (qf_cmp(g, h) == RLC_EQ);
				} else {
					result = 1;
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		qf_free(w);
		qf_free(s);
		qf_free(g);
		qf_free(h);
		bn_free(l);
		bn_free(r);
		bn_free(e);
		bn_free(two);
	}
	return result;
}

int cp_clvdf_dec_opt(bn_t x, size_t t, const qf_t u, const qf_t z, const qf_t y) {
	qf_t w, s, g, h;
	bn_t l, r, e, two;
	int result = 0;

	qf_null(w);
	qf_null(s);
	qf_null(g);
	qf_null(h);
	bn_null(l);
	bn_null(r);
	bn_null(e);
	bn_null(two);

	RLC_TRY {
		qf_new(w);
		qf_new(s);
		qf_new(g);
		qf_new(h);
		bn_new(l);
		bn_new(r);
		bn_new(e);
		bn_new(two);

		if (qf_has_dsc(u, &(core_get()->qf_dk)) &&
				qf_has_dsc(y, &(core_get()->qf_dk)) &&
				qf_has_dsc(z, &(core_get()->qf_d))) {
			clvdf_map_p(l, t, u, y);

			/* r = 2^t mod l, by exponentiation on the delay rather than on 2^t */
			bn_set_dig(two, 2);
			bn_set_dig(r, t);
			bn_mxp(r, two, r, l);

			/*
				* W = z^l * L(u)^(q*r) * L(y)^-(q*(r+1)), with L the bare lift.
				*
				* psi_q is the lift followed by a q-th power, and that power can be
				* folded into the exponents applied here instead, since
				*
				*   z^l L(u)^(qr) L(y)^-(q(r+1))
				*     = [L(pi)^l L(u)^r L(y)^-(r+1)]^q F^(m*l)
				*
				* because the bracket lies in the kernel, which the q-th power kills,
				* while the kernel component sits outside it and survives. Folding on
				* its own trades two short exponentiations for two longer exponents and
				* is close to a wash; the gain is that the two lifted terms then share
				* one simultaneous exponentiation.
				*
				* The lift is taken directly rather than through qf_psi, so the
				* identity above is what keeps this correct. An edit that moves either
				* lifted term out of the shared power would break it silently.
				*/
			qf_exp(w, z, l, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_copa(s, u);
			qf_lift(s, s);
			qf_copa(g, y);
			qf_lift(g, g);
			qf_neg(g, g);
			bn_mul(e, r, &(core_get()->qf_q));
			bn_add_dig(two, r, 1);
			bn_mul(two, two, &(core_get()->qf_q));
			qf_exp_sim(h, s, e, g, two, &(core_get()->qf_d), &(core_get()->qf_b));
			qf_com(w, w, h, 0, &(core_get()->qf_b));

			/* the result must lie in the kernel, where the logarithm is easy */
			qf_phi(s, w, 1);
			if (qf_is_one(s)) {
				qf_kern(x, w);

				/*
					* g = u*y^-1 has to be the oracle image. That check binds the triple to
					* the input, and it also settles the sign: the kernel logarithm comes
					* back only up to the sign of the class.
					*/
				qf_neg(h, y);
				qf_com(g, u, h, 0, &(core_get()->qf_bk));
				clvdf_map_g(h, t, x);
				if (qf_cmp(g, h) != RLC_EQ) {
					bn_sub(x, &(core_get()->qf_q), x);
					bn_mod(x, x, &(core_get()->qf_q));
					clvdf_map_g(h, t, x);
					result = (qf_cmp(g, h) == RLC_EQ);
				} else {
					result = 1;
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		qf_free(w);
		qf_free(s);
		qf_free(g);
		qf_free(h);
		bn_free(l);
		bn_free(r);
		bn_free(e);
		bn_free(two);
	}
	return result;
}

int cp_clvdf_ver(size_t t, const bn_t x, const qf_t u, const qf_t z, const qf_t y) {
	bn_t d;
	int result = 0;

	bn_null(d);

	RLC_TRY {
		bn_new(d);
		/*
		 * Either decoder settles this, and the optimised one is at worst equal,
		 * so verification takes that.
		 */
		result = cp_clvdf_dec_opt(d, t, u, z, y) && (bn_cmp(d, x) == RLC_EQ);
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(d);
	}
	return result;
}