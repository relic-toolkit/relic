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
 * Implementation of the CL-RSA argument for public exponent three.
 *
 * The argument shows that a CL ciphertext encrypts an e-th root modulo the
 * conductor of a public value, without revealing the root.  The fixed map
 * Y -> Y^e is represented by an addition chain, and the argument commits to
 * the chain's intermediate values and proves their multiplication relations.
 *
 * For e = 3 the optimal chain is 1, 2, 3, giving chain length L = 2 with
 *
 *   alpha_0 = 1                      a_0 = Y
 *   alpha_1 = alpha_0 + alpha_0      a_1 = Y^2,  j_1 = k_1 = 0
 *   alpha_2 = alpha_1 + alpha_0      a_2 = Y^3,  j_2 = 1, k_2 = 0
 *
 * under the conventions E_0 = c2, rho_0 = rho and rho_L = 0.  There is a
 * single intermediate commitment E_1, and the batched auxiliary proof reduces
 * to one challenge coordinate.  For L = 2 the parameter condition
 * N >= (L - 2)(C - 1) + 1 is vacuous, so the challenge space is constrained
 * only by C < min{p, q}, which is what makes every challenge difference
 * invertible modulo the conductor.
 *
 * Commitments are ordered E_1, A_G, A, D_1, M_1, D_2, M_2 and responses are
 * ordered z_1, s_1, t_1, z_2, s_2, t_2, rho^, a^.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#define clrsa_dsc(c)	(c->compact ? &(core_get()->qf_dk) : &(core_get()->qf_d))
#define clrsa_bnd(c)	(c->compact ? &(core_get()->qf_bk) : &(core_get()->qf_b))

/**
 * Raises a form to a possibly negative power.
 *
 * The responses of the argument are integers over Z rather than residues, so
 * the verifier needs exponentiation by signed exponents.
 *
 * @param[out] r			- the resulting quadratic form.
 * @param[in] f				- the form to exponentiate.
 * @param[in] n				- the possibly negative exponent.
 * @param[in] dsc			- the discriminant.
 * @param[in] bnd			- the partial reduction bound.
 */
static void clrsa_exp(qf_t r, const qf_t f, const bn_t n, const bn_t dsc,
		const bn_t bnd) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		bn_copy(t, n);
		if (bn_sign(t) == RLC_NEG) {
			bn_neg(t, t);
			qf_exp(r, f, t, dsc, bnd);
			qf_neg(r, r);
			qf_rdc(r, r);
		} else {
			qf_exp(r, f, t, dsc, bnd);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

/**
 * Largest number of exponents grouped onto one squaring chain.
 */
#define CLRSA_SHR		5

/**
 * Raises one base to several exponents, sharing a single squaring chain.
 *
 * Proceeding from the least significant digit squares the base rather than the
 * accumulators, so one chain of the length of the longest exponent serves every
 * accumulator and only the compositions remain proportional to the number of
 * exponents. The exponents are recoded in non-adjacent form, which lowers the
 * density of non-zero digits from one half to one third; the signed digits cost
 * nothing here, the inverse of (a, b, c) being (a, -b, c). What is verified is
 * unchanged, each equation still being tested on its own and the arithmetic
 * being exact.
 *
 * @param[out] r			- the resulting quadratic forms.
 * @param[in] f				- the common base.
 * @param[in] n				- the possibly negative exponents.
 * @param[in] k				- the number of exponents, at most CLRSA_SHR.
 * @param[in] dsc			- the discriminant.
 * @param[in] bnd			- the partial reduction bound.
 */
static void clrsa_exp_shr(qf_t *r, const qf_t f, bn_t *n, int k,
		const bn_t dsc, const bn_t bnd) {
	int8_t *naf[CLRSA_SHR];
	bn_t a[CLRSA_SHR];
	size_t len[CLRSA_SHR], i, m = 0;
	int j;
	qf_t w;

	qf_null(w);
	for (j = 0; j < k; j++) {
		bn_null(a[j]);
		naf[j] = NULL;
	}

	RLC_TRY {
		qf_new(w);
		for (j = 0; j < k; j++) {
			/* The recoding takes the magnitude; the sign is applied after. */
			bn_new(a[j]);
			bn_abs(a[j], n[j]);
			len[j] = bn_bits(a[j]) + 1;
			naf[j] = RLC_ALLOCA(int8_t, len[j] + 1);
			if (naf[j] == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			bn_rec_naf(naf[j], &len[j], a[j], 2);
			if (len[j] > m) {
				m = len[j];
			}
			qf_set_one(r[j], dsc);
		}

		qf_copy(w, f);
		for (i = 0; i < m; i++) {
			for (j = 0; j < k; j++) {
				if (i < len[j] && naf[j][i] != 0) {
					qf_com(r[j], r[j], w, naf[j][i] < 0, bnd);
				}
			}
			if (i + 1 < m) {
				qf_dup(w, w, bnd);
			}
		}

		for (j = 0; j < k; j++) {
			qf_rdc(r[j], r[j]);
			if (bn_sign(n[j]) == RLC_NEG) {
				qf_neg(r[j], r[j]);
				qf_rdc(r[j], r[j]);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		qf_free(w);
		for (j = 0; j < k; j++) {
			bn_free(a[j]);
			if (naf[j] != NULL) {
				RLC_FREE(naf[j]);
			}
		}
	}
}

/**
 * Samples uniformly from the symmetric interval [-r, r].
 *
 * @param[out] c			- the resulting value.
 * @param[in] r				- the bound of the interval.
 */
static void clrsa_rand(bn_t c, const bn_t r) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		bn_lsh(t, r, 1);
		bn_add_dig(t, t, 1);
		bn_rand_mod(c, t);
		bn_sub(c, c, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

/**
 * Computes the masking bound R = 2^(sec-1) * (N + C - 2) * (bound - 1), for
 * the CL exponent bound.
 *
 * @param[out] r			- the resulting bound.
 */
static void clrsa_bound(bn_t r) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		/* N + C - 2, with C = 2^RLC_CLRSA_CHL. */
		bn_set_dig(t, 1);
		bn_lsh(t, t, RLC_CLRSA_CHL);
		bn_add(r, &(core_get()->qf_q), t);
		bn_sub_dig(r, r, 2);
		/* times the CL exponent bound, less one */
		cp_clhe_bnd(t);
		bn_sub_dig(t, t, 1);
		bn_mul(r, r, t);
		/* times 2^(sec-1) */
		bn_lsh(r, r, RLC_CLRSA_SEC - 1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

/**
 * Derives both challenge coordinates from the statement and first message.
 *
 * @param[out] eta			- the resulting common challenge.
 * @param[out] xi			- the resulting auxiliary challenge.
 * @param[in] cmt			- the commitments.
 * @param[in] x				- the public value.
 * @param[in] c1			- the first ciphertext component.
 * @param[in] c2			- the second ciphertext component.
 */
static void clrsa_chal(bn_t eta, bn_t xi, const qf_t *cmt, const bn_t x,
		const qf_t c1, const qf_t c2) {
	uint8_t *buf = NULL, dig[RLC_MD_LEN];
	size_t la, lb, len, off;
	qf_t all[2 + RLC_CLRSA_CMT];
	bn_t bound;

	bn_null(bound);

	for (size_t i = 0; i < RLC_CLRSA_CMT + 2; i++) {
		qf_null(all[i]);
	}

	RLC_TRY {
		bn_new(bound);
		bn_set_dig(bound, 1);
		bn_lsh(bound, bound, RLC_CLRSA_CHL);

		qf_new(all[0]);
		qf_new(all[1]);
		qf_copy(all[0], c1);
		qf_copy(all[1], c2);
		for (size_t i = 0; i < RLC_CLRSA_CMT; i++) {
			qf_new(all[i + 2]);
			qf_copy(all[i + 2], cmt[i]);
		}

		len = bn_size_bin(x) + 2;
		for (size_t i = 0; i < 2 + RLC_CLRSA_CMT; i++) {
			len += bn_size_bin(all[i]->a) + bn_size_bin(all[i]->b) + 8;
		}
		buf = RLC_ALLOCA(uint8_t, len);
		if (buf == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		/* Leading byte domain separates the two coordinates. */
		off = 1;
		la = bn_size_bin(x);
		buf[off++] = (uint8_t)la;
		bn_write_bin(buf + off, la, x);
		off += la;
		for (size_t i = 0; i < 2 + RLC_CLRSA_CMT; i++) {
			la = bn_size_bin(all[i]->a);
			lb = bn_size_bin(all[i]->b);
			buf[off++] = (uint8_t)la;
			bn_write_bin(buf + off, la, all[i]->a);
			off += la;
			buf[off++] = (uint8_t)lb;
			bn_write_bin(buf + off, lb, all[i]->b);
			off += lb;
			/* Sign of b matters: (a, b, c) and (a, -b, c) are inverses. */
			buf[off++] = (bn_sign(all[i]->b) == RLC_NEG);
		}

		buf[0] = 1;
		md_map(dig, buf, off);
		bn_read_bin(eta, dig, RLC_MD_LEN);
		bn_mod(eta, eta, bound);

		buf[0] = 2;
		md_map(dig, buf, off);
		bn_read_bin(xi, dig, RLC_MD_LEN);
		bn_mod(xi, xi, bound);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(bound);
		if (buf != NULL) {
			RLC_FREE(buf);
		}
		for (size_t i = 0; i < RLC_CLRSA_CMT + 2; i++) {
			qf_free(all[i]);
		}
	}
}

/**
 * Verifies the CL-RSA argument against an explicit challenge.
 *
 * @param[in] cmt			- the commitments.
 * @param[in] rsp			- the responses.
 * @param[in] eta			- the common challenge.
 * @param[in] xi			- the auxiliary batch challenge.
 * @param[in] c				- the CL public parameters.
 * @param[in] x				- the public value whose root is encrypted.
 * @param[in] c1			- the first ciphertext component.
 * @param[in] c2			- the second ciphertext component.
 * @param[in] hh			- the lifted public key.
 * @return 1 if the argument is accepted, 0 otherwise.
 */
int cp_clrsa_chk(const qf_t *cmt, const bn_t *rsp, const bn_t eta,
		const bn_t xi, const clhe_t c, const bn_t x, const qf_t c1,
		const qf_t c2, const qf_t hh) {
	ctx_t *ctx = core_get();
	int i, result = 0;
	bn_t e[CLRSA_SHR], t;
	qf_t hp[5], cp[3], ep[2], g0, l, r, p;

	bn_null(t);
	for (i = 0; i < CLRSA_SHR; i++) {
		bn_null(e[i]);
	}
	for (i = 0; i < 5; i++) {
		qf_null(hp[i]);
	}
	for (i = 0; i < 3; i++) {
		qf_null(cp[i]);
	}
	for (i = 0; i < 2; i++) {
		qf_null(ep[i]);
	}
	qf_null(g0);
	qf_null(l);
	qf_null(r);
	qf_null(p);

	RLC_TRY {
		bn_new(t);
		for (i = 0; i < CLRSA_SHR; i++) {
			bn_new(e[i]);
		}
		for (i = 0; i < 5; i++) {
			qf_new(hp[i]);
		}
		for (i = 0; i < 3; i++) {
			qf_new(cp[i]);
		}
		for (i = 0; i < 2; i++) {
			qf_new(ep[i]);
		}
		qf_new(g0);
		qf_new(l);
		qf_new(r);
		qf_new(p);

		/*
		 * Three bases recur between the equations, so the exponentiations are
		 * grouped by base and each group evaluated on one squaring chain. The
		 * five exponents applied to the lifted key are those of the masking
		 * interval and dominate the cost. Note also that the challenge power
		 * of E_1 is required by two equations, and here is computed once.
		 */
		bn_copy(e[0], rsp[1]);
		bn_copy(e[1], rsp[4]);
		bn_copy(e[2], rsp[2]);
		bn_copy(e[3], rsp[5]);
		bn_copy(e[4], rsp[6]);
		clrsa_exp_shr(hp, hh, e, 5, &(ctx->qf_d),
				&(ctx->qf_b));

		bn_copy(e[0], rsp[0]);
		bn_copy(e[1], rsp[3]);
		bn_copy(e[2], eta);
		clrsa_exp_shr(cp, c2, e, 3, &(ctx->qf_d),
				&(ctx->qf_b));

		bn_copy(e[0], eta);
		bn_copy(e[1], xi);
		clrsa_exp_shr(ep, cmt[0], e, 2, &(ctx->qf_d),
				&(ctx->qf_b));

		result = 1;

		/* (1) h^{s_1} = A_G * c1^eta, in the order c1 lives in. */
		clrsa_exp(g0, c->h, rsp[1], clrsa_dsc(c), clrsa_bnd(c));
		qf_exp(r, c1, eta, clrsa_dsc(c), clrsa_bnd(c));
		qf_com(r, r, cmt[1], 0, clrsa_bnd(c));
		result &= (qf_cmp(g0, r) == RLC_EQ);

		/* (2) i = 1, j_1 = 0: D_1 * c2^eta = hh^{s_1} * f^{z_1}. */
		qf_com(l, cp[2], cmt[3], 0, &(ctx->qf_b));
		cp_clhe_powf(p, c, rsp[0]);
		qf_com(r, hp[0], p, 0, &(ctx->qf_b));
		result &= (qf_cmp(l, r) == RLC_EQ);

		/* (2) i = 2, j_2 = 1: D_2 * E_1^eta = hh^{s_2} * f^{z_2}. */
		qf_com(l, ep[0], cmt[5], 0, &(ctx->qf_b));
		cp_clhe_powf(p, c, rsp[3]);
		qf_com(r, hp[1], p, 0, &(ctx->qf_b));
		result &= (qf_cmp(l, r) == RLC_EQ);

		/* (3) A * E_1^{xi} = hh^{rho^} * f^{a^}. */
		qf_com(l, ep[1], cmt[2], 0, &(ctx->qf_b));
		cp_clhe_powf(p, c, rsp[7]);
		qf_com(r, hp[4], p, 0, &(ctx->qf_b));
		result &= (qf_cmp(l, r) == RLC_EQ);

		/* (4) i = 1, k_1 = 0: c2^{z_1} = M_1 * E_1^eta * hh^{t_1}. */
		qf_com(r, ep[0], cmt[4], 0, &(ctx->qf_b));
		qf_com(r, r, hp[2], 0, &(ctx->qf_b));
		result &= (qf_cmp(cp[0], r) == RLC_EQ);

		/* (5) k_L = 0: c2^{z_2} = M_2 * f^{eta * X} * hh^{t_2}. */
		bn_mul(t, eta, x);
		bn_mod(t, t, &(ctx->qf_q));
		cp_clhe_powf(p, c, t);
		qf_com(r, p, cmt[6], 0, &(ctx->qf_b));
		qf_com(r, r, hp[3], 0, &(ctx->qf_b));
		result &= (qf_cmp(cp[1], r) == RLC_EQ);
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(t);
		for (i = 0; i < CLRSA_SHR; i++) {
			bn_free(e[i]);
		}
		for (i = 0; i < 5; i++) {
			qf_free(hp[i]);
		}
		for (i = 0; i < 3; i++) {
			qf_free(cp[i]);
		}
		for (i = 0; i < 2; i++) {
			qf_free(ep[i]);
		}
		qf_free(g0);
		qf_free(l);
		qf_free(r);
		qf_free(p);
	}
	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_clrsa_set(qf_t hh, const clhe_t c, const clhe_pk_t pk) {
	int result = RLC_OK;

	RLC_TRY {
		/*
		 * The argument works entirely in the order of conductor N, so it needs
		 * the public key materialized there.  In the compact variant the key
		 * lives in the maximal order and cp_clhe_enc lifts on the fly; lifting
		 * once here trades one psi at setup for one per exponentiation.
		 */
		if (c->compact) {
			qf_psi(hh, pk->pk, &(core_get()->qf_d), &(core_get()->qf_b));
		} else {
			qf_copy(hh, pk->pk);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	return result;
}

int cp_clrsa_cmt(qf_t *cmt, bn_t *aux, const clhe_t c, const bn_t y,
		const qf_t c2, const qf_t hh) {
	int result = RLC_OK;
	bn_t r;
	qf_t p, q;

	bn_null(r);
	qf_null(p);
	qf_null(q);

	RLC_TRY {
		bn_new(r);
		qf_new(p);
		qf_new(q);

		clrsa_bound(r);

		/* Chain values: a_0 = Y and a_1 = Y^2 mod N. */
		bn_sqr(aux[0], y);
		bn_mod(aux[0], aux[0], &(core_get()->qf_q));

		/* Masks: rho_1, d_1, d_2 modulo their own ranges, rest symmetric. */
		cp_clhe_bnd(q->a);
		bn_rand_mod(aux[1], q->a);
		bn_rand_mod(aux[2], &(core_get()->qf_q));
		bn_rand_mod(aux[3], &(core_get()->qf_q));
		clrsa_rand(aux[4], r);
		clrsa_rand(aux[5], r);
		clrsa_rand(aux[6], r);
		clrsa_rand(aux[7], r);
		clrsa_rand(aux[8], r);
		bn_rand_mod(aux[9], &(core_get()->qf_q));

		/* E_1 = hh^rho_1 * f^a_1 */
		qf_exp(cmt[0], hh, aux[1], &(core_get()->qf_d), &(core_get()->qf_b));
		cp_clhe_powf(p, c, aux[0]);
		qf_com(cmt[0], cmt[0], p, 0, &(core_get()->qf_b));
		qf_rdc(cmt[0], cmt[0]);

		/* A_G = h^tau_1, in whichever order the CL generator lives in. */
		clrsa_exp(cmt[1], c->h, aux[4], clrsa_dsc(c), clrsa_bnd(c));

		/* A = hh^rho~ * f^a~ */
		clrsa_exp(cmt[2], hh, aux[8], &(core_get()->qf_d), &(core_get()->qf_b));
		cp_clhe_powf(p, c, aux[9]);
		qf_com(cmt[2], cmt[2], p, 0, &(core_get()->qf_b));
		qf_rdc(cmt[2], cmt[2]);

		/* D_i = hh^tau_i * f^d_i */
		clrsa_exp(cmt[3], hh, aux[4], &(core_get()->qf_d), &(core_get()->qf_b));
		cp_clhe_powf(p, c, aux[2]);
		qf_com(cmt[3], cmt[3], p, 0, &(core_get()->qf_b));
		qf_rdc(cmt[3], cmt[3]);

		clrsa_exp(cmt[5], hh, aux[5], &(core_get()->qf_d), &(core_get()->qf_b));
		cp_clhe_powf(p, c, aux[3]);
		qf_com(cmt[5], cmt[5], p, 0, &(core_get()->qf_b));
		qf_rdc(cmt[5], cmt[5]);

		/* M_i = E_{k_i}^{d_i} * hh^nu_i, with k_1 = k_2 = 0 so E_0 = c2. */
		qf_exp(cmt[4], c2, aux[2], &(core_get()->qf_d), &(core_get()->qf_b));
		clrsa_exp(q, hh, aux[6], &(core_get()->qf_d), &(core_get()->qf_b));
		qf_com(cmt[4], cmt[4], q, 0, &(core_get()->qf_b));
		qf_rdc(cmt[4], cmt[4]);

		qf_exp(cmt[6], c2, aux[3], &(core_get()->qf_d), &(core_get()->qf_b));
		clrsa_exp(q, hh, aux[7], &(core_get()->qf_d), &(core_get()->qf_b));
		qf_com(cmt[6], cmt[6], q, 0, &(core_get()->qf_b));
		qf_rdc(cmt[6], cmt[6]);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(r);
		qf_free(p);
		qf_free(q);
	}
	return result;
}

int cp_clrsa_rsp(bn_t *rsp, const bn_t *aux, const bn_t eta, const bn_t xi,
		const bn_t y, const bn_t rho) {
	int result = RLC_OK;
	bn_t t, u;

	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(t);
		bn_new(u);

		/*
		 *   z_i = d_i + eta * a_{j_i} mod N,  j_1 = 0, j_2 = 1
		 *   s_i = tau_i + eta * rho_{j_i},    rho_0 = rho, rho_1 = aux[1]
		 *   t_i = (z_i - d_i) * rho_{k_i} - nu_i - eta * rho_i, rho_2 = 0
		 */
		bn_mul(t, eta, y);
		bn_add(t, t, aux[2]);
		bn_mod(rsp[0], t, &(core_get()->qf_q));
		bn_mul(t, eta, aux[0]);
		bn_add(t, t, aux[3]);
		bn_mod(rsp[3], t, &(core_get()->qf_q));

		bn_mul(t, eta, rho);
		bn_add(rsp[1], aux[4], t);
		bn_mul(t, eta, aux[1]);
		bn_add(rsp[4], aux[5], t);

		bn_sub(t, rsp[0], aux[2]);
		bn_mul(t, t, rho);
		bn_sub(t, t, aux[6]);
		bn_mul(u, eta, aux[1]);
		bn_sub(rsp[2], t, u);

		bn_sub(t, rsp[3], aux[3]);
		bn_mul(t, t, rho);
		bn_sub(rsp[5], t, aux[7]);

		/* rho^ = rho~ + xi * rho_1 and a^ = a~ + xi * a_1 mod N. */
		bn_mul(t, xi, aux[1]);
		bn_add(rsp[6], aux[8], t);
		bn_mul(t, xi, aux[0]);
		bn_add(t, t, aux[9]);
		bn_mod(rsp[7], t, &(core_get()->qf_q));
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(u);
	}
	return result;
}

int cp_clrsa_sig(qf_t *cmt, bn_t *rsp, const clhe_t c, const bn_t y,
		const bn_t rho, const qf_t c1, const qf_t c2, const bn_t x,
		const qf_t hh) {
	int i, result = RLC_OK;
	bn_t eta, xi, aux[RLC_CLRSA_AUX];

	bn_null(eta);
	bn_null(xi);
	for (i = 0; i < RLC_CLRSA_AUX; i++) {
		bn_null(aux[i]);
	}

	RLC_TRY {
		bn_new(eta);
		bn_new(xi);
		for (i = 0; i < RLC_CLRSA_AUX; i++) {
			bn_new(aux[i]);
		}

		/*
		 * Commit, bind both challenge coordinates to the first message, then
		 * respond.  The commit and response phases must stay separate: the
		 * commitments depend on freshly sampled masks, so re-running the
		 * prover to obtain them would not reproduce the same first message.
		 */
		result = cp_clrsa_cmt(cmt, aux, c, y, c2, hh);
		if (result == RLC_OK) {
			clrsa_chal(eta, xi, cmt, x, c1, c2);
			result = cp_clrsa_rsp(rsp, aux, eta, xi, y, rho);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(eta);
		bn_free(xi);
		for (i = 0; i < RLC_CLRSA_AUX; i++) {
			bn_free(aux[i]);
		}
	}
	return result;
}

int cp_clrsa_ver(const qf_t *cmt, const bn_t *rsp, const clhe_t c,
		const bn_t x, const qf_t c1, const qf_t c2, const qf_t hh) {
	int result = 0;
	bn_t eta, xi;

	bn_null(eta);
	bn_null(xi);

	RLC_TRY {
		bn_new(eta);
		bn_new(xi);
		clrsa_chal(eta, xi, cmt, x, c1, c2);
		result = cp_clrsa_chk(cmt, rsp, eta, xi, c, x, c1, c2, hh);
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(eta);
		bn_free(xi);
	}
	return result;
}