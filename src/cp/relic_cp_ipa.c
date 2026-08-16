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
 * Domain separator for the Fiat-Shamir transcript.
 */
#define CP_IPA_DST		"smklhs/InPrd~/v1"

/**
 * Size of the per-round hash input: statement digest, L, R, prior challenge.
 */
#define CP_IPA_BUF		(RLC_MD_LEN + 3 * RLC_FP_BYTES + 2)

/**
 * Digests the statement into a fixed-size prefix for every challenge.
 *
 * Covers pp = (n, g, u), the commitment M and the claimed inner product c.
 *
 * @param[out] dst			- the resulting digest, RLC_MD_LEN bytes.
 * @param[in] g				- the generator vector.
 * @param[in] u				- the auxiliary generator.
 * @param[in] m				- the commitment M = g^a.
 * @param[in] c				- the claimed inner product, reduced mod the order.
 * @param[in] n				- the number of generators.
 */
static void cp_ipa_bind(uint8_t *dst, const ec_t *g, const ec_t u,
		const ec_t m, const bn_t c, size_t n) {
	const size_t unit = RLC_FP_BYTES + 1;
	size_t len = sizeof(CP_IPA_DST) - 1 + 8 + (n + 2) * unit + RLC_FP_BYTES;
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
		ec_write_bin(ptr, unit, m, 1);
		ptr += unit;
		bn_write_bin(ptr, RLC_FP_BYTES, c);

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
 * Derives x_M, the challenge shifting u in Protocol 1.  Labelled
 * distinctly from the round chain so the two cannot collide.
 *
 * @return 0 if the challenge is zero, in which case the caller must fail.
 */
static int cp_ipa_shift(bn_t x, const uint8_t *dst, const bn_t r) {
	uint8_t buf[RLC_MD_LEN + 1], hash[RLC_MD_LEN];

	memcpy(buf, dst, RLC_MD_LEN);
	buf[RLC_MD_LEN] = 0x01;
	md_map(hash, buf, sizeof(buf));
	bn_read_bin(x, hash, RLC_MD_LEN);
	bn_mod(x, x, r);

	return !bn_is_zero(x);
}

/**
 * Derives round challenge i.  The chain carries x_{i-1} itself, not its
 * square: squaring mod a prime is 2-to-1 and so fails to separate x from -x.
 *
 * @return 0 if the challenge is zero, in which case the caller must fail.
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

size_t cp_ipa_rounds(size_t n) {
	size_t k = 0, m;

	if (n <= 1) {
		return 0;
	}
	/* ceil(log2(n)) = bit length of (n - 1).  The previous expression took
	 * the bit length of n, which is floor(log2(n)) + 1 and so spent an extra
	 * round -- one (L, R) pair per proof, plus a full round of folding
	 * against infinity points -- whenever n is an exact power of two. */
	m = n - 1;
	do {
		k++;
	} while (m >>= 1);
	return k;
}

int cp_ipa_prv(bn_t y, ec_t p, ec_t *ls, ec_t *rs, const ec_t *g, const bn_t *a,
		const ec_t u, size_t n) {
	uint8_t buf[CP_IPA_BUF], dst[RLC_MD_LEN];
	int result = RLC_OK;
	size_t m, k;
	bn_t *b, *c, t, r, cc, c_l, c_r, x;
	ec_t s, uu, *h;

	k = cp_ipa_rounds(n);
	b = RLC_ALLOCA(bn_t, 1 << k);
	c = RLC_ALLOCA(bn_t, 1 << k);
	h = RLC_ALLOCA(ec_t, 1 << k);

	ec_null(s);
	ec_null(uu);
	bn_null(r);
	bn_null(t);
	bn_null(x);
	bn_null(cc);
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
		ec_new(s);
		ec_new(uu);
		bn_new(r);
		bn_new(t);
		bn_new(x);
		bn_new(cc);
		bn_new(c_l);
		bn_new(c_r);

		bn_zero(cc);
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
			bn_add(cc, cc, c[i]);
		}

		ec_curve_get_ord(r);
		bn_mod(cc, cc, r);

		/* The commitment M = g^a is what crosses the interface, per Fig. 5;
		 * P = M * u^(x_M * c) is reconstructed on both sides. */
		ec_mul_sim_lot(p, g, a, n);
		ec_norm(p, p);

		/* Draw x_M once the statement is fixed, then run
		 * the argument against the shifted generator u' = u^(x_M). */
		cp_ipa_bind(dst, g, u, p, cc, n);
		if (!cp_ipa_shift(x, dst, r)) {
			RLC_THROW(ERR_NO_VALID);
		}
		ec_mul(uu, u, x);
		ec_norm(uu, uu);

		memcpy(buf, dst, RLC_MD_LEN);
		m = (1 << k);
		bn_zero(x);
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
			ec_mul(s, uu, c_l);
			ec_add(ls[i], ls[i], s);
			ec_norm(ls[i], ls[i]);
			ec_mul_sim_lot(rs[i], h, c + m, m);
			ec_mul(s, uu, c_r);
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
		}
		bn_copy(y, c[0]);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	} RLC_FINALLY {
		ec_free(s);
		ec_free(uu);
		bn_free(r);
		bn_free(t);
		bn_free(x);
		bn_free(cc);
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

int cp_ipa_ver(const bn_t y, const ec_t p, const bn_t c, const ec_t *ls,
		const ec_t *rs, const ec_t *g, const ec_t u, size_t n) {
	uint8_t buf[CP_IPA_BUF], dst[RLC_MD_LEN];
	int result = 1;
	size_t k, big, len, o;
	bn_t t, r, w, xm, *ch, *iv, *e;
	ec_t q, *h;

	k = cp_ipa_rounds(n);
	big = ((size_t)1) << k;                 /* padded length N */
	len = n + 2 * k + 2;                    /* bases in the multi-exp */

	ch = RLC_ALLOCA(bn_t, k + 1);           /* challenges x_i           */
	iv = RLC_ALLOCA(bn_t, k + 1);           /* inverses   x_i^-1        */
	e  = RLC_ALLOCA(bn_t, big + 2 * k + 2); /* s-vector, then scalars   */
	h  = RLC_ALLOCA(ec_t, len);             /* bases                    */

	ec_null(q);
	bn_null(r);
	bn_null(t);
	bn_null(w);
	bn_null(xm);

	if (n == 0 || ch == NULL || iv == NULL || e == NULL || h == NULL) {
		RLC_FREE(ch);
		RLC_FREE(iv);
		RLC_FREE(e);
		RLC_FREE(h);
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	RLC_TRY {
		ec_new(q);
		bn_new(r);
		bn_new(t);
		bn_new(w);
		bn_new(xm);
		for (size_t i = 0; i < k + 1; i++) {
			bn_null(ch[i]); bn_new(ch[i]);
			bn_null(iv[i]); bn_new(iv[i]);
		}
		for (size_t i = 0; i < big + 2 * k + 2; i++) {
			bn_null(e[i]); bn_new(e[i]);
		}
		for (size_t i = 0; i < len; i++) {
			ec_null(h[i]); ec_new(h[i]);
		}

		ec_curve_get_ord(r);
		bn_mod(w, c, r);

		/*-------------------------------------------------------------------
		 * 1. x_M and the whole challenge chain, derived before any group
		 * arithmetic.  Identical to cp_ipa_prv, which is why both call the
		 * same three helpers.
		 *-----------------------------------------------------------------*/
		cp_ipa_bind(dst, g, u, p, w, n);
		if (!cp_ipa_shift(xm, dst, r)) {
			result = 0;
		}

		memcpy(buf, dst, RLC_MD_LEN);
		bn_zero(t);
		for (size_t i = 0; result && i < k; i++) {
			if (!cp_ipa_next(t, buf, ls[i], rs[i], r)) {
				result = 0;
				break;
			}
			bn_copy(ch[i], t);
		}

		if (result) {
			/* k == 0 (n == 1): bn_mod_inv_sim reads c[n-1] and indexes out
			 * of bounds when handed a length of zero. */
			if (k > 0) {
				bn_mod_inv_sim(iv, ch, r, k);
			}

			/*---------------------------------------------------------------
			 * 2. s-vector by prefix doubling, O(N) field multiplications,
			 * replacing the O(N) two-base scalar multiplications the
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
				bn_mul(e[0], e[0], iv[i]);
				bn_mod(e[0], e[0], r);
			}
			for (size_t sz = 1, i = k; i >= 1; i--, sz <<= 1) {
				bn_sqr(t, ch[i - 1]);
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
			 * b^(0) = 1^N, padded slots included.  The u slot then carries
			 *
			 *   x_M * (c - y b)
			 *
			 * since the argument runs against u' = u^(x_M) and
			 * P = M * u'^c, so the final identity is
			 *
			 *   M + sum x_i^2 L_i + sum x_i^-2 R_i
			 *     + (c - y b) u' - y sum s_j g_j == O.
			 *-------------------------------------------------------------*/
			bn_set_dig(w, 1);
			for (size_t i = 0; i < k; i++) {
				bn_add(t, ch[i], iv[i]);
				bn_mod(t, t, r);
				bn_mul(w, w, t);
				bn_mod(w, w, r);
			}
			bn_mod(t, y, r);
			bn_mul(t, t, w);
			bn_mod(t, t, r);                /* t = y b mod r */
			bn_mod(w, c, r);
			if (bn_cmp(w, t) == RLC_LT) {
				bn_add(w, w, r);
			}
			bn_sub(w, w, t);                /* w = c - y b mod r */
			bn_mul(w, w, xm);
			bn_mod(w, w, r);

			o = n;
			for (size_t i = 0; i < k; i++) {
				bn_sqr(e[o], ch[i]);
				bn_mod(e[o], e[o], r);
				ec_copy(h[o], ls[i]);
				o++;
				bn_sqr(e[o], iv[i]);
				bn_mod(e[o], e[o], r);
				ec_copy(h[o], rs[i]);
				o++;
			}
			bn_copy(e[o], w);
			ec_copy(h[o], u);
			o++;
			bn_set_dig(e[o], 1);
			ec_copy(h[o], p);               /* M, coefficient 1 */

			/*---------------------------------------------------------------
			 * 5. One multi-exponentiation; accept iff the result is O.
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
		bn_free(w);
		bn_free(xm);
		for (size_t i = 0; i < k + 1; i++) {
			bn_free(ch[i]);
			bn_free(iv[i]);
		}
		for (size_t i = 0; i < big + 2 * k + 2; i++) {
			bn_free(e[i]);
		}
		for (size_t i = 0; i < len; i++) {
			ec_free(h[i]);
		}
		RLC_FREE(ch);
		RLC_FREE(iv);
		RLC_FREE(e);
		RLC_FREE(h);
	}
	return result;
}