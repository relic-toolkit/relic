/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of inner product arguments.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Domain separator for the Fiat-Shamir chain.
 */
#define CP_IPA_DST		"smklhs/InPrd~/v1"

/**
 * Size of the per-round hash input: statement digest, L, R, previous
 * challenge.
 */
#define CP_IPA_BUF		(RLC_MD_LEN + 3 * RLC_FP_BYTES + 2)

/**
 * Digests the statement (pp, P) into a fixed-size prefix for the challenge
 * chain, where pp = (n, g, u).  Fixed-width encodings throughout, so the
 * concatenation admits no reparsing as a different (n, g).
 *
 * Fig. 4 of the paper specifies x_i = H2(pp, P, {L_j,R_j}, {x_j}); binding
 * through a digest keeps the per-round buffer at RLC_MD_LEN extra bytes
 * rather than growing it by n points.
 */
static void cp_ipa_bind(uint8_t *dst, const ec_t *g, const ec_t u,
		const ec_t p, size_t n) {
	const size_t unit = RLC_FP_BYTES + 1;
	size_t len = sizeof(CP_IPA_DST) - 1 + 8 + (n + 2) * unit;
	uint8_t *ptr, *buf = RLC_ALLOCA(uint8_t, len);

	RLC_TRY {
		if (buf == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		memcpy(buf, CP_IPA_DST, sizeof(CP_IPA_DST) - 1);
		ptr = buf + sizeof(CP_IPA_DST) - 1;

		for (size_t i = 0; i < 8; i++) {
			ptr[i] = (uint8_t)((uint64_t)n >> (8 * (7 - i)));
		}
		ptr += 8;

		for (size_t i = 0; i < n; i++) {
			ec_write_bin(ptr, unit, g[i], 1);
			ptr += unit;
		}
		ec_write_bin(ptr, unit, u, 1);
		ptr += unit;
		ec_write_bin(ptr, unit, p, 1);

		md_map(dst, buf, len);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		RLC_FREE(buf);
	}
}

/**
 * Derives challenge i.  The chain carries x_{i-1} itself, not its square:
 * squaring mod a prime is 2-to-1, so a squared chain fails to separate x
 * from -x.  Callers keep x^2 in a separate variable.
 *
 * Returns 0 if the challenge is zero, in which case the caller must fail --
 * a zero challenge has no inverse and the round is undefined.
 */
static int cp_ipa_next(bn_t x, uint8_t *buf, const ec_t l, const ec_t rr,
		const bn_t r) {
	uint8_t hash[RLC_MD_LEN];

	ec_write_bin(buf + RLC_MD_LEN, RLC_FP_BYTES + 1, l, 1);
	ec_write_bin(buf + RLC_MD_LEN + RLC_FP_BYTES + 1, RLC_FP_BYTES + 1, rr, 1);
	bn_write_bin(buf + RLC_MD_LEN + 2 * RLC_FP_BYTES + 2, RLC_FP_BYTES, x);
	md_map(hash, buf, CP_IPA_BUF);
	bn_read_bin(x, hash, RLC_MD_LEN);
	bn_mod(x, x, r);

	return !bn_is_zero(x);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_ipa_prv(bn_t y, ec_t p, ec_t *ls, ec_t *rs, const ec_t *g, const bn_t *a,
		const ec_t u, size_t n) {
	uint8_t buf[CP_IPA_BUF];
	int result = RLC_OK;
	size_t m = n, k = 0;
	bn_t *b, *c, t, r, c_l, c_r, x, x2, t2;
	ec_t q, s, *h;

	do {
		k++;
	} while (m >>= 1);
	k = (n == 1 ? 0 : k);
	b = RLC_ALLOCA(bn_t, 1 << k);
	c = RLC_ALLOCA(bn_t, 1 << k);
	h = RLC_ALLOCA(ec_t, 1 << k);

	ec_null(q);
	ec_null(s);
	bn_null(r);
	bn_null(t);
	bn_null(x);
	bn_null(x2);
	bn_null(t2);
	bn_null(c_l);
	bn_null(c_r);

	if (n == 0 || b == NULL || c == NULL || h == NULL) {
		RLC_FREE(b);
		RLC_FREE(c);
		RLC_FREE(h);
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	RLC_TRY {
		ec_new(q);
		ec_new(s);
		bn_new(r);
		bn_new(t);
		bn_new(x);
		bn_new(x2);
		bn_new(t2);
		bn_new(c_l);
		bn_new(c_r);

		bn_zero(c_l);
		for (size_t i = 0; i < (1 << k); i++) {
			bn_null(b[i]);
			bn_null(c[i]);
			ec_null(h[i]);
			bn_new(b[i]);
			bn_new(c[i]);
			ec_new(h[i]);
			bn_set_dig(b[i], 1);
			if (i < n) {
				ec_copy(h[i], g[i]);
				bn_copy(c[i], a[i]);
			} else {
				ec_set_infty(h[i]);
				bn_zero(c[i]);
			}
			bn_add(c_l, c_l, c[i]);
		}

		ec_curve_get_ord(r);
		bn_mod(c_l, c_l, r);
		ec_mul_sim_lot(p, g, a, n);
		ec_mul(q, u, c_l);
		ec_add(p, p, q);
		ec_norm(p, p);

		/* Bind (n, g, u, P) into every challenge. */
		cp_ipa_bind(buf, g, u, p, n);

		m = (1 << k);
		bn_zero(x);
		ec_copy(q, p);
		for (size_t i = 0; i < k; i++) {
			m = m >> 1;
			bn_zero(c_l);
			bn_zero(c_r);
			for (size_t j = 0; j < m; j++) {
				bn_mul(t, c[j], b[m + j]);
				bn_add(c_l, c_l, t);
				bn_mul(t, c[m + j], b[j]);
				bn_add(c_r, c_r, t);
			}
			bn_mod(c_l, c_l, r);
			bn_mod(c_r, c_r, r);
			ec_mul_sim_lot(ls[i], h + m, c, m);
			ec_mul(s, u, c_l);
			ec_add(ls[i], ls[i], s);
			ec_norm(ls[i], ls[i]);
			ec_mul_sim_lot(rs[i], h, c + m, m);
			ec_mul(s, u, c_r);
			ec_add(rs[i], rs[i], s);
			ec_norm(rs[i], rs[i]);

			if (!cp_ipa_next(x, buf, ls[i], rs[i], r)) {
				RLC_THROW(ERR_NO_VALID);
			}

			bn_mod_inv(t, x, r);
			for (size_t j = 0; j < m; j++) {
				ec_mul_sim(h[j], h[j], t, h[m + j], x);
				bn_mul(c[j], c[j], x);
				bn_mul(c[m + j], c[m + j], t);
				bn_add(c[j], c[j], c[m + j]);
				bn_mod(c[j], c[j], r);
				bn_mul(b[j], b[j], t);
				bn_mul(b[m + j], b[m + j], x);
				bn_add(b[j], b[j], b[m + j]);
				bn_mod(b[j], b[j], r);
			}

			/* x and t are the running chain values and must survive the
			 * round intact; the squares go to scratch. */
			bn_sqr(x2, x);
			bn_mod(x2, x2, r);
			bn_sqr(t2, t);
			bn_mod(t2, t2, r);
			ec_mul_sim(s, ls[i], x2, rs[i], t2);
			ec_add(q, q, s);
		}
		ec_norm(q, q);
		bn_copy(y, c[0]);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		ec_free(q);
		ec_free(s);
		bn_free(r);
		bn_free(t);
		bn_free(x);
		bn_free(x2);
		bn_free(t2);
		bn_free(c_l);
		bn_free(c_r);
		for (size_t i = 0; i < (1 << k); i++) {
			bn_free(b[i]);
			bn_free(c[i]);
			ec_free(h[i]);
		}
		RLC_FREE(b);
		RLC_FREE(c);
		RLC_FREE(h);
	}
	return result;
}

int cp_ipa_ver(const bn_t y, const ec_t p, const ec_t *ls, const ec_t *rs,
		const ec_t *g, const ec_t u, size_t n) {
	uint8_t buf[CP_IPA_BUF];
	int result = 1;
	size_t m = n, k = 0, big, len, o;
	bn_t t, r, x, *c, *d, *e;
	ec_t q, *h;

	do {
		k++;
	} while (m >>= 1);
	k = (n == 1 ? 0 : k);
	big = ((size_t)1) << k;                 /* padded length N */
	len = n + 2 * k + 2;                    /* bases in the multi-exp */

	c = RLC_ALLOCA(bn_t, k + 1);            /* challenges x_i           */
	d = RLC_ALLOCA(bn_t, k + 1);            /* inverses   x_i^-1        */
	e = RLC_ALLOCA(bn_t, big + 2 * k + 2);  /* s-vector, then scalars   */
	h = RLC_ALLOCA(ec_t, len);              /* bases                    */

	ec_null(q);
	bn_null(r);
	bn_null(t);
	bn_null(x);

	if (n == 0 || c == NULL || d == NULL || e == NULL || h == NULL) {
		RLC_FREE(c);
		RLC_FREE(d);
		RLC_FREE(e);
		RLC_FREE(h);
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	RLC_TRY {
		ec_new(q);
		bn_new(r);
		bn_new(t);
		bn_new(x);
		for (size_t i = 0; i < k + 1; i++) {
			bn_null(c[i]); bn_new(c[i]);
			bn_null(d[i]); bn_new(d[i]);
		}
		for (size_t i = 0; i < big + 2 * k + 2; i++) {
			bn_null(e[i]); bn_new(e[i]);
		}
		for (size_t i = 0; i < len; i++) {
			ec_null(h[i]); ec_new(h[i]);
		}

		ec_curve_get_ord(r);

		/*-------------------------------------------------------------------
		 * 1. Challenge chain, hoisted out of the folding loop.
		 *
		 * Identical derivation to cp_ipa_prv: same binding digest, same
		 * unsquared chain.  Since no challenge depends on a folded group
		 * element, the whole chain runs before any group arithmetic.
		 *-----------------------------------------------------------------*/
		cp_ipa_bind(buf, g, u, p, n);

		bn_zero(x);
		for (size_t i = 0; i < k; i++) {
			if (!cp_ipa_next(x, buf, ls[i], rs[i], r)) {
				result = 0;
				break;
			}
			bn_copy(c[i], x);
		}

		if (result) {
			/* k == 0 (n == 1): bn_mod_inv_sim reads c[n-1] and indexes out
			 * of bounds when handed a length of zero. */
			if (k > 0) {
				bn_mod_inv_sim(d, c, r, k);
			}

			/*---------------------------------------------------------------
			 * 2. s-vector by prefix doubling, O(N) field multiplications,
			 * replacing the O(N) two-base scalar multiplications that the
			 * generator folding used to cost.
			 *
			 *   s_j = prod_i x_i^(+1 if bit i of j set, -1 otherwise)
			 *
			 * with bit 1 the most significant of k.  Round (i+1) controls
			 * bit (k-1-i), so walking rounds last-to-first keeps the filled
			 * region a contiguous prefix and the write offset always equals
			 * the current prefix length.
			 *-------------------------------------------------------------*/
			bn_set_dig(e[0], 1);
			for (size_t i = 0; i < k; i++) {
				bn_mul(e[0], e[0], d[i]);
				bn_mod(e[0], e[0], r);
			}
			for (size_t sz = 1, i = k; i >= 1; i--, sz <<= 1) {
				bn_sqr(t, c[i - 1]);
				bn_mod(t, t, r);
				for (size_t j = 0; j < sz; j++) {
					bn_mul(e[sz + j], e[j], t);
					bn_mod(e[sz + j], e[sz + j], r);
				}
			}

			/*---------------------------------------------------------------
			 * 3. Scale the generator slots by -y.  Padded positions j >= n
			 * carry the infinity point in the folding version and so
			 * contribute nothing; they are dropped here.
			 *-------------------------------------------------------------*/
			bn_mod(t, y, r);
			if (!bn_is_zero(t)) {
				bn_sub(t, r, t);            /* -y mod r, kept positive */
			}
			for (size_t j = 0; j < n; j++) {
				bn_mul(e[j], e[j], t);
				bn_mod(e[j], e[j], r);
				ec_copy(h[j], g[j]);
			}

			/*---------------------------------------------------------------
			 * 4. b = <s, 1^N> = prod_i (x_i + x_i^-1), which holds because
			 * b^(0) = 1^N -- including the padded slots, which the folding
			 * version also initialises to 1.  Then the L/R, u and P slots.
			 *
			 * Tail scalars are written from index n onwards, overwriting
			 * s-values of padded positions that are no longer needed.
			 *-------------------------------------------------------------*/
			bn_set_dig(x, 1);
			for (size_t i = 0; i < k; i++) {
				bn_add(t, c[i], d[i]);
				bn_mod(t, t, r);
				bn_mul(x, x, t);
				bn_mod(x, x, r);
			}
			bn_mod(t, y, r);
			if (!bn_is_zero(t)) {
				bn_sub(t, r, t);
			}
			bn_mul(x, x, t);
			bn_mod(x, x, r);                /* x = -y b mod r */

			o = n;
			for (size_t i = 0; i < k; i++) {
				bn_sqr(e[o], c[i]);
				bn_mod(e[o], e[o], r);
				ec_copy(h[o], ls[i]);
				o++;
				bn_sqr(e[o], d[i]);
				bn_mod(e[o], e[o], r);
				ec_copy(h[o], rs[i]);
				o++;
			}
			bn_copy(e[o], x);
			ec_copy(h[o], u);
			o++;
			bn_set_dig(e[o], 1);
			ec_copy(h[o], p);

			/*---------------------------------------------------------------
			 * 5. One multi-exponentiation:
			 *
			 *   P + sum x_i^2 L_i + sum x_i^-2 R_i - y sum s_j g_j - y b u
			 *
			 * accept iff it is the point at infinity.
			 *-------------------------------------------------------------*/
			ec_mul_sim_lot(q, h, e, len);
			result = ec_is_infty(q);
		}
	} RLC_CATCH_ANY {
		result = 0;
	} RLC_FINALLY {
		ec_free(q);
		bn_free(r);
		bn_free(t);
		bn_free(x);
		for (size_t i = 0; i < k + 1; i++) {
			bn_free(c[i]);
			bn_free(d[i]);
		}
		for (size_t i = 0; i < big + 2 * k + 2; i++) {
			bn_free(e[i]);
		}
		for (size_t i = 0; i < len; i++) {
			ec_free(h[i]);
		}
		RLC_FREE(c);
		RLC_FREE(d);
		RLC_FREE(e);
		RLC_FREE(h);
	}
	return result;
}