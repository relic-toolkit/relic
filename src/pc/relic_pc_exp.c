/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * Implementation of exponentiation in pairing groups.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if FP_PRIME <= 1536

/**
 * Apply Frobenius endomorphism in different pairing-friendly curve families.
 *
 * @param[in] c			- the result.
 * @param[in] a			- the extension field element to exponentiate.
 */
static void gt_psi(gt_t c, const gt_t a) {
	gt_t b;

	gt_null(b);

	RLC_TRY {
		gt_new(b);

		switch (ep_curve_is_pairf()) {
			case EP_K16:
				/* u = (2*p^5 - p) mod r */
				gt_frb(b, a, 1);
				gt_frb(c, b, 4);
				gt_sqr(c, c);
				gt_inv(b, b);
				gt_mul(c, c, b);
				break;
			case EP_AFG16:
				/* u = -p^5 mod r */
				gt_frb(c, a, 5);
				gt_inv(c, c);
				break;
			case EP_SG18:
				/* -3*u = (2*p^2 - p^5) mod r */
				gt_frb(b, a, 5);
				gt_inv(b, b);
				gt_frb(c, a, 2);
				gt_sqr(c, c);
				gt_mul(c, c, b);
				break;
			case EP_K18:
				/* For KSS18, we have that x = p^4 - 3*p = (p^3 - 3)p mod n. */
				gt_sqr(b, a);
				gt_mul(b, b, a);
				gt_frb(c, a, 3);
				gt_inv(b, b);
				gt_mul(c, c, b);
				gt_frb(c, c, 1);
				break;
			case EP_SG54:
				/* 3*u^2 = p^11 mod r. */
				gt_frb(c, a, 11);
				break;
			case EP_FM18:
				/* For FM18, we have that u = (p^4-p) mod r. */
				gt_frb(b, a, 3);
				gt_inv(b, b);
				gt_mul(c, a, b);
				gt_frb(c, c, 1);
				gt_inv(c, c);
				break;
			default:
				gt_frb(c, a, 1);
				break;
		}	
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		gt_free(b);
	}
}

#endif

/**
 * Size of a precomputation table using the double-table comb method.
 */
#define RLC_GT_TABLE		(1 << (RLC_WIDTH - 2))

#if FP_PRIME < 1536 && FP_PRIME != 544

/**
 * Exponentiates one or two elements from G_T simultaneously, decomposing the
 * exponents with the Frobenius endomorphism and interleaving w-NAF recodings.
 *
 * @param[out] e			- the result.
 * @param[in] a				- the first element to exponentiate.
 * @param[in] b				- the first exponent.
 * @param[in] c				- the second element to exponentiate, or NULL.
 * @param[in] d				- the second exponent, or NULL.
 * @param[in] f				- the maximum Frobenius power.
 */
static void gt_exp_gls_naf(gt_t e, const gt_t a, const bn_t b, const gt_t c,
		const bn_t d, size_t f) {
	size_t l, m = (c == NULL ? 1 : 2), w = RLC_WIDTH;
	int8_t *naf  = RLC_ALLOCA(int8_t, m * f * (RLC_FP_BITS + 1));
	int8_t n0, *s = RLC_ALLOCA(int8_t, m * f);
	int one = 1;
	gt_t q, *t = RLC_ALLOCA(gt_t, m * f * RLC_GT_TABLE);
	bn_t n, u, *_b = RLC_ALLOCA(bn_t, m * f);
	size_t *_l = RLC_ALLOCA(size_t, m * f);

	if (naf == NULL || s == NULL || t == NULL || _b == NULL || _l == NULL) {
		RLC_FREE(naf);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (bn_is_zero(b)) {
		RLC_FREE(naf);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
		return gt_set_unity(e);
	}

	bn_null(n);
	bn_null(u);
	gt_null(q);

	for (size_t i = 0; i < m * f; i++) {
		bn_null(_b[i]);
	}
	for (size_t i = 0; i < m * f * RLC_GT_TABLE; i++) {
		gt_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		gt_new(q);
		for (size_t i = 0; i < m * f; i++) {
			bn_new(_b[i]);
			for (size_t j = 0; j < RLC_GT_TABLE; j++) {
				gt_new(t[i * RLC_GT_TABLE + j]);
			}
		}

		ep_curve_frbase(u);
		gt_get_ord(n);
		for (size_t k = 0; k < m; k++) {
			bn_abs(_b[k * f], (k == 0 ? b : d));
			bn_mod(_b[k * f], _b[k * f], n);
			if (bn_sign(k == 0 ? b : d) == RLC_NEG) {
				bn_neg(_b[k * f], _b[k * f]);
			}
			bn_rec_frb(_b + k * f, f, _b[k * f], u, n, ep_curve_get_rec(),
					ep_curve_is_pairf() == EP_BN);
		}

		l = 0;
		for (size_t i = 0; i < m * f; i++) {
			l = RLC_MAX(l, bn_bits(_b[i]));
		}
		if (l < bn_bits(u) / 2) {
			w = 2;
		}

		l = 0;
		for (size_t i = 0; i < m * f; i++) {
			s[i] = bn_sign(_b[i]);
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf + i * (RLC_FP_BITS + 1), &_l[i], _b[i], w);
			l = RLC_MAX(l, _l[i]);
		}

		/* Build a table of odd powers for each of the m * f subexponents. */
		for (size_t k = 0; k < m; k++) {
			gt_t *_t = t + k * f * RLC_GT_TABLE;
			int8_t *_s = s + k * f;

			if (ep_curve_is_pairf() == EP_K16 ||
					ep_curve_is_pairf() == EP_AFG16 || ep_curve_embed() == 18) {
				/* The endomorphism is expensive, so apply it once per table. */
				gt_copy(_t[0], (k == 0 ? a : c));
				for (size_t i = 1; i < f; i++) {
					gt_psi(_t[i * RLC_GT_TABLE], _t[(i - 1) * RLC_GT_TABLE]);
				}
				for (size_t i = 0; i < f; i++) {
					gt_copy(q, _t[i * RLC_GT_TABLE]);
					if (_s[i] == RLC_NEG) {
						gt_inv(q, _t[i * RLC_GT_TABLE]);
					}
					if (w > 2) {
						gt_sqr(_t[i * RLC_GT_TABLE], q);
						gt_mul(_t[i * RLC_GT_TABLE + 1], _t[i * RLC_GT_TABLE], q);
						for (size_t j = 2; j < RLC_GT_TABLE; j++) {
							gt_mul(_t[i * RLC_GT_TABLE + j],
									_t[i * RLC_GT_TABLE + j - 1],
									_t[i * RLC_GT_TABLE]);
						}
					}
					gt_copy(_t[i * RLC_GT_TABLE], q);
				}
			} else {
				gt_copy(q, (k == 0 ? a : c));
				if (_s[0] == RLC_NEG) {
					gt_inv(q, q);
				}
				if (w > 2) {
					gt_sqr(_t[0], q);
					gt_mul(_t[1], _t[0], q);
					for (size_t j = 2; j < RLC_GT_TABLE; j++) {
						gt_mul(_t[j], _t[j - 1], _t[0]);
					}
				}
				gt_copy(_t[0], q);
				for (size_t i = 1; i < f; i++) {
					for (size_t j = 0; j < ((size_t)1 << (w - 2)); j++) {
						gt_psi(_t[i * RLC_GT_TABLE + j],
								_t[(i - 1) * RLC_GT_TABLE + j]);
						if (_s[i] != _s[i - 1]) {
							gt_inv(_t[i * RLC_GT_TABLE + j],
									_t[i * RLC_GT_TABLE + j]);
						}
					}
				}
			}
		}

		/* The accumulator is copied, not squared or multiplied, while it is
		 * still the identity. */
		gt_set_unity(e);
		for (int j = l - 1; j >= 0; j--) {
			if (!one) {
				gt_sqr(e, e);
			}

			for (size_t i = 0; i < m * f; i++) {
				n0 = naf[i * (RLC_FP_BITS + 1) + j];
				if (n0 > 0) {
					if (one) {
						gt_copy(e, t[i * RLC_GT_TABLE + n0 / 2]);
					} else {
						gt_mul(e, e, t[i * RLC_GT_TABLE + n0 / 2]);
					}
					one = 0;
				}
				if (n0 < 0) {
					if (one) {
						gt_inv(e, t[i * RLC_GT_TABLE - n0 / 2]);
					} else {
						gt_inv(q, t[i * RLC_GT_TABLE - n0 / 2]);
						gt_mul(e, e, q);
					}
					one = 0;
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		gt_free(q);
		for (size_t i = 0; i < m * f; i++) {
			bn_free(_b[i]);
			for (size_t j = 0; j < RLC_GT_TABLE; j++) {
				gt_free(t[i * RLC_GT_TABLE + j]);
			}
		}
		RLC_FREE(naf);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
	}
}

/**
 * Exponentiates an element from G_T using the variable-time GLS-SAC method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to exponentiate.
 * @param[in] b				- the exponent.
 * @param[in] f				- the maximum Frobenius power.
 */
static void gt_exp_gls_sac(gt_t c, const gt_t a, const bn_t b, size_t d,
		size_t f) {
	size_t l, s = (1 << (f / d - 1));
	bn_t n, *_b = RLC_ALLOCA(bn_t, f), u;
	int8_t col, *e = RLC_ALLOCA(int8_t, d);
	int8_t *sac = RLC_ALLOCA(int8_t, d * f * RLC_FP_BITS);
	gt_t *q = RLC_ALLOCA(gt_t, f), *t = RLC_ALLOCA(gt_t, d * s);

	if (sac == NULL || e == NULL || t == NULL || _b == NULL || q == NULL) {
		RLC_FREE(sac);
		RLC_FREE(e);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(q);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	bn_null(n);
	bn_null(u);

	for (size_t i = 0; i < f; i++) {
		bn_null(_b[i]);
		gt_null(q[i]);
	}
	for (size_t i = 0; i < d * s; i++) {
		gt_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (size_t i = 0; i < f; i++) {
			bn_new(_b[i]);
			gt_new(q[i]);
		}
		for (size_t i = 0; i < d; i++) {
			for (size_t j = 0; j < s; j++) {
				gt_new(t[i * s + j]);
			}
		}

		ep_curve_frbase(u);
		gt_get_ord(n);
		bn_mod(_b[0], b, n);
		bn_rec_frb(_b, f, _b[0], u, n, ep_curve_get_rec(),
				ep_curve_is_pairf() == EP_BN);

		gt_copy(q[0], a);
		for (size_t i = 1; i < f; i++) {
			gt_psi(q[i], q[i - 1]);
		}
		for (size_t i = 0; i < f; i++) {
			gt_inv(c, q[i]);
			if (bn_sign(_b[i]) == RLC_NEG) {
				gt_copy(q[i], c);
			}
			bn_abs(_b[i], _b[i]);
		}
		for (size_t i = 0; i < d; i++) {
			e[i] = bn_is_even(_b[i * f / d]);
			bn_add_dig(_b[i * f / d], _b[i * f / d], e[i]);
		}
		
		for (size_t i = 0; i < d; i++) {
			gt_copy(t[i * s], q[i * f / d]);
			for (size_t j = 1; j < s; j++) {
				l = util_bits_dig(j);
				gt_mul(t[i * s + j], t[i * s + (j ^ (1 << (l - 1)))],
						q[l + i * f / d]);
			}
			l = RLC_FP_BITS;
			bn_rec_sac(sac + i * f * RLC_FP_BITS, &l, _b + i * f/d, u, d, f/d,
					bn_bits(n), ep_curve_is_pairf() == EP_BN);
		}

		/* The first digit initializes the accumulator. */
		for (int j = l - 1; j >= 0; j--) {
			if (j < (int)l - 1) {
				gt_sqr(c, c);
			}
			for (size_t i = 0; i < d; i++) {
				col = 0;
				for (int k = f / d - 1; k > 0; k--) {
					col <<= 1;
					col += sac[i * f * RLC_FP_BITS + k * l + j];
				}

				if (j == (int)l - 1 && i == 0) {
					if (sac[i * f * RLC_FP_BITS + j]) {
						gt_inv(c, t[i * s + col]);
					} else {
						gt_copy(c, t[i * s + col]);
					}
				} else if (sac[i * f * RLC_FP_BITS + j]) {
					gt_inv(q[1], t[i * s + col]);
					gt_mul(c, c, q[1]);
				} else {
					gt_mul(c, c, t[i * s + col]);
				}
			}
		}

		for (size_t i = 0; i < d; i++) {
			if (e[i]) {
				gt_inv(q[1], q[i * f / d]);
				gt_mul(c, c, q[1]);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		for (size_t i = 0; i < f; i++) {
			bn_free(_b[i]);
			gt_free(q[i]);
		}
		for (size_t i = 0; i < d; i++) {
			for (size_t j = 0; j < s; j++) {
				gt_free(t[i * s + j]);
			}
		}
		RLC_FREE(e);
		RLC_FREE(_b);
		RLC_FREE(q);
		RLC_FREE(t);
		RLC_FREE(sac);
	}
}

#endif

#if FP_PRIME < 1536 && FP_PRIME != 544

/**
 * Exponentiates an element from G_T in constant time using the GLS-SAC method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to exponentiate.
 * @param[in] b				- the exponent.
 * @param[in] f				- the maximum Frobenius power.
 */
static void gt_exp_reg_sac(gt_t c, const gt_t a, const bn_t b, size_t d,
		size_t f) {
	size_t l, s = (1 << (f / d - 1));
	bn_t n, *_b = RLC_ALLOCA(bn_t, f), u;
	int8_t col, *e = RLC_ALLOCA(int8_t, d);
	int8_t *sac = RLC_ALLOCA(int8_t, d * f * RLC_FP_BITS);
	gt_t *q = RLC_ALLOCA(gt_t, f), *t = RLC_ALLOCA(gt_t, d * s);

	if (sac == NULL || e == NULL || t == NULL || _b == NULL || q == NULL) {
		RLC_FREE(sac);
		RLC_FREE(e);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(q);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	bn_null(n);
	bn_null(u);

	for (size_t i = 0; i < f; i++) {
		bn_null(_b[i]);
		gt_null(q[i]);
	}
	for (size_t i = 0; i < d * s; i++) {
		gt_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (size_t i = 0; i < f; i++) {
			bn_new(_b[i]);
			gt_new(q[i]);
		}
		for (size_t i = 0; i < d; i++) {
			for (size_t j = 0; j < s; j++) {
				gt_new(t[i * s + j]);
			}
		}

		ep_curve_frbase(u);
		gt_get_ord(n);
		/* The decomposition runs in constant time for |b| < n. */
		bn_rec_frb(_b, f, b, u, n, ep_curve_get_rec(),
				ep_curve_is_pairf() == EP_BN);

		gt_copy(q[0], a);
		for (size_t i = 1; i < f; i++) {
			gt_psi(q[i], q[i - 1]);
		}
		for (size_t i = 0; i < f; i++) {
			gt_inv(c, q[i]);
			gt_copy_sec(q[i], c, bn_sign(_b[i]) == RLC_NEG);
			bn_abs(_b[i], _b[i]);
		}
		for (size_t i = 0; i < d; i++) {
			/* Make it odd in constant time, as it is even if e = 1. */
			e[i] = bn_is_even(_b[i * f / d]);
			_b[i * f / d]->dp[0] |= e[i];
		}
		
		for (size_t i = 0; i < d; i++) {
			gt_copy(t[i * s], q[i * f / d]);
			for (size_t j = 1; j < s; j++) {
				l = util_bits_dig(j);
				gt_mul(t[i * s + j], t[i * s + (j ^ (1 << (l - 1)))],
						q[l + i * f/d]);
			}
			l = RLC_FP_BITS;
			bn_rec_sac(sac + i * f * RLC_FP_BITS, &l, _b + i * f/d, u, d, f/d,
					bn_bits(n), ep_curve_is_pairf() == EP_BN);
		}

		/* The first digit initializes the accumulator, which depends only
		 * on the loop counters. */
		for (int j = l - 1; j >= 0; j--) {
			if (j < (int)l - 1) {
				gt_sqr(c, c);
			}
			for (size_t i = 0; i < d; i++) {
				col = 0;
				for (int k = f / d - 1; k > 0; k--) {
					col <<= 1;
					col += sac[i * f * RLC_FP_BITS + k * l + j];
				}

				for (size_t m = 0; m < s; m++) {
					gt_copy_sec(q[1], t[i * s + m], m == (size_t)col);
				}
				gt_inv(q[2], q[1]);
				gt_copy_sec(q[1], q[2], sac[i * f * RLC_FP_BITS + j]);
				if (j == (int)l - 1 && i == 0) {
					gt_copy(c, q[1]);
				} else {
					gt_mul(c, c, q[1]);
				}
			}
		}

		for (size_t i = 0; i < d; i++) {
			gt_inv(q[1], q[i * f / d]);
			gt_mul(q[1], q[1], c);
			gt_copy_sec(c, q[1], e[i]);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		for (size_t i = 0; i < f; i++) {
			bn_free(_b[i]);
			gt_free(q[i]);
		}
		for (size_t i = 0; i < d; i++) {
			for (size_t j = 0; j < s; j++) {
				gt_free(t[i * s + j]);
			}
		}
		RLC_FREE(e);
		RLC_FREE(_b);
		RLC_FREE(q);
		RLC_FREE(t);
		RLC_FREE(sac);
	}
}

#endif

#if FP_PRIME == 1536 || FP_PRIME == 544

/**
 * Exponentiates an element from G_T in constant time.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to exponentiate.
 * @param[in] b				- the exponent.
 * @param[in] f				- the maximum Frobenius power.
 */
static void gt_exp_reg_gls(gt_t c, const gt_t a, const bn_t b, size_t f) {
	int8_t c0, n0, *reg  = RLC_ALLOCA(int8_t, f * (RLC_FP_BITS + 1));
	int8_t *e = RLC_ALLOCA(int8_t, f), *s = RLC_ALLOCA(int8_t, f);
	gt_t q, w, *t = RLC_ALLOCA(gt_t, f * RLC_GT_TABLE);
	bn_t n, u, *_b = RLC_ALLOCA(bn_t, f);
	size_t l, len, *_l = RLC_ALLOCA(size_t, f);

	if (reg == NULL || e == NULL || s == NULL || t == NULL || _b == NULL ||
			_l == NULL) {
		RLC_FREE(reg);
		RLC_FREE(e);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (bn_is_zero(b)) {
		RLC_FREE(reg);
		RLC_FREE(e);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
		return gt_set_unity(c);
	}

	bn_null(n);
	bn_null(u);
	gt_null(q);
	gt_null(w);

	for (size_t i = 0; i < f; i++) {
		bn_null(_b[i]);
	}
	for (size_t i = 0; i < f * RLC_GT_TABLE; i++) {
		gt_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		gt_new(q);
		gt_new(w);
		for (size_t i = 0; i < f; i++) {
			bn_new(_b[i]);
			for (size_t j = 0; j < RLC_GT_TABLE; j++) {
				gt_new(t[i * RLC_GT_TABLE + j]);
			}
		}

		ep_curve_frbase(u);
		gt_get_ord(n);
		if (f > 1) {
			/* The decomposition runs in constant time for |b| < n. */
			bn_rec_frb(_b, f, b, u, n, ep_curve_get_rec(),
					ep_curve_is_pairf() == EP_BN);
			len = bn_bits(u) + (ep_curve_is_pairf() == EP_BN);
		} else {
			/* Without a decomposition, recode the full exponent. */
			bn_abs(_b[0], b);
			bn_mod(_b[0], _b[0], n);
			if (bn_sign(b) == RLC_NEG) {
				bn_neg(_b[0], _b[0]);
			}
			len = bn_bits(n);
		}

		l = 0;
		gt_copy(t[0], a);
		for (size_t i = 0; i < f; i++) {
			s[i] = bn_sign(_b[i]);
			bn_abs(_b[i], _b[i]);
			e[i] = bn_is_even(_b[i]);
			_b[i]->dp[0] |= e[i];

			_l[i] = RLC_FP_BITS + 1;
			bn_rec_reg(reg + i * (RLC_FP_BITS + 1), &_l[i], _b[i], len, RLC_WIDTH);
			l = RLC_MAX(l, _l[i]);
			/* Apply Frobenius before flipping sign to build table. */
			if (i > 0) {
				gt_psi(t[i * RLC_GT_TABLE], t[(i - 1) * RLC_GT_TABLE]);
			}
		}

		for (size_t i = 0; i < f; i++) {
			gt_inv(q, t[i * RLC_GT_TABLE]);
			gt_copy_sec(q, t[i * RLC_GT_TABLE], s[i] == RLC_POS);
			if (RLC_WIDTH > 2) {
				gt_sqr(t[i * RLC_GT_TABLE], q);
				gt_mul(t[i * RLC_GT_TABLE + 1], t[i * RLC_GT_TABLE], q);
				for (size_t j = 2; j < RLC_GT_TABLE; j++) {
					gt_mul(t[i * RLC_GT_TABLE + j], t[i * RLC_GT_TABLE + j - 1],
							t[i * (RLC_GT_TABLE)]);
				}
			}
			gt_copy(t[i * RLC_GT_TABLE], q);
		}

		/* The first digit initializes the accumulator, which depends only
		 * on the loop counters. */
		for (int j = l - 1; j >= 0; j--) {
			for (size_t i = 0; j < (int)l - 1 && i < RLC_WIDTH - 1; i++) {
				gt_sqr(c, c);
			}

			for (size_t i = 0; i < f; i++) {
				n0 = reg[i * (RLC_FP_BITS + 1) + j];
				c0 = (n0 >> 7);
				n0 = ((n0 ^ c0) - c0) >> 1;

				for (size_t m = 0; m < RLC_GT_TABLE; m++) {
					gt_copy_sec(w, t[i * RLC_GT_TABLE + m], m == (size_t)n0);
				}

				gt_inv(q, w);
				gt_copy_sec(q, w, c0 == 0);
				if (j == (int)l - 1 && i == 0) {
					gt_copy(c, q);
				} else {
					gt_mul(c, c, q);
				}

			}
		}

		for (size_t i = 0; i < f; i++) {
			/* Tables are built with points already negated, so no need here. */
			gt_inv(q, t[i * RLC_GT_TABLE]);
			gt_mul(q, c, q);
			gt_copy_sec(c, q, e[i]);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		gt_free(q);
		gt_free(w);
		for (size_t i = 0; i < f; i++) {
			bn_free(_b[i]);
			for (size_t j = 0; j < RLC_GT_TABLE; j++) {
				gt_free(t[i * RLC_GT_TABLE + j]);
			}
		}
		RLC_FREE(reg);
		RLC_FREE(e);
		RLC_FREE(s);
		RLC_FREE(t);
		RLC_FREE(_b);
		RLC_FREE(_l);
	}
}

#endif

/* Embedding degrees 12, 18, 24 and 48, whose fields have cyclotomic cubing. */
#if RLC_GT_EMBED % 6 == 0 && RLC_GT_EMBED <= 48

/**
 * Number of tau-adic expansions in the tau-adic method, k/6 for embedding
 * degree k.
 */
#define RLC_GT_TW		(RLC_GT_EMBED / 6)

/**
 * Exponentiates an element from G_T using the tau-adic method. The Frobenius
 * pi acts on G_T with pi^(k/3) as a cube root of unity w and pi^(k/6) as
 * 1 + w. The decomposition b = b_0 + b_1 * psi + ... + b_(2H-1) * psi^(2H-1)
 * along psi = pi * mu, for H = k/6 and mu = w - 2 on KSS18 curves or 1
 * otherwise, regroups as the sum of the coefficients
 * b_i * mu^i + b_(i+H) * mu^(i+H) * (1 + w) in Z[w] times pi^i for i < H, and
 * each coefficient is recoded as a tau-adic NAF in base tau = 1 - w. As
 * tau^2 = -3w, Horner's rule takes a cyclotomic cube every two digits. The
 * table of each pi^i(a) holds a, a^2, a * tau(a) and their images under tau,
 * for tau(x) = x / w(x), and the images of the entries under w are Frobenius
 * maps computed when needed.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to exponentiate.
 * @param[in] b				- the exponent.
 */
static void gt_exp_tw_imp(gt_t c, const gt_t a, const bn_t b) {
	const int h = RLC_GT_TW, k = RLC_GT_EMBED;
	int8_t naf[RLC_GT_TW][RLC_FP_BITS + 1];
	size_t l, len[RLC_GT_TW];
	int d, f, j, v, first = 1, mu[2 * RLC_GT_TW][2];
	bn_t n, x, y, _b[2 * RLC_GT_TW], r[2];
	gt_t q, *t = RLC_ALLOCA(gt_t, 6 * RLC_GT_TW);

	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	bn_null_all(n, x, y);
	bn_null_all(r[0], r[1]);
	gt_null(q);
	for (int i = 0; i < 2 * h; i++) {
		bn_null(_b[i]);
	}
	for (int i = 0; i < 6 * h; i++) {
		gt_null(t[i]);
	}

	RLC_TRY {
		bn_new_all(n, x, y);
		bn_new_all(r[0], r[1]);
		gt_new(q);
		for (int i = 0; i < 2 * h; i++) {
			bn_new(_b[i]);
		}
		for (int i = 0; i < 6 * h; i++) {
			gt_new(t[i]);
		}

		/* The coefficients mu^i * (1 + w)^(i / H) in Z[w], with
		 * (a0 + a1 * w)(c0 + c1 * w) =
		 * (a0c0 - a1c1) + (a0c1 + a1c0 - a1c1) * w, as w^2 = -1 - w. */
		mu[0][0] = 1;
		mu[0][1] = 0;
		for (int i = 1; i < 2 * h; i++) {
			if (ep_curve_is_pairf() == EP_K18) {
				mu[i][0] = -2 * mu[i - 1][0] - mu[i - 1][1];
				mu[i][1] = mu[i - 1][0] - 3 * mu[i - 1][1];
			} else {
				mu[i][0] = mu[i - 1][0];
				mu[i][1] = mu[i - 1][1];
			}
		}
		for (int i = h; i < 2 * h; i++) {
			v = mu[i][0];
			mu[i][0] = v - mu[i][1];
			mu[i][1] = v;
		}

		gt_get_ord(n);
		ep_curve_frbase(x);
		/* The decomposition runs in constant time for |b| < n. */
		bn_rec_frb(_b, 2 * h, b, x, n, ep_curve_get_rec(),
				ep_curve_is_pairf() == EP_BN);
		l = 0;
		for (int i = 0; i < h; i++) {
			bn_zero(r[0]);
			bn_zero(r[1]);
			for (int o = i; o < 2 * h; o += h) {
				for (int m = 0; m < 2; m++) {
					v = mu[o][m];
					bn_mul_dig(y, _b[o], (v < 0 ? -v : v));
					if (v < 0) {
						bn_neg(y, y);
					}
					bn_add(r[m], r[m], y);
				}
			}
			len[i] = RLC_FP_BITS + 1;
			bn_rec_etnaf(naf[i], &len[i], r[0], r[1]);
			l = RLC_MAX(l, len[i]);
		}

		/* Table of a, a^2, a * tau(a), tau(a), tau(a)^2 = tau(a^2) and
		 * tau(a * tau(a)), then its images under pi, which commutes with
		 * w and tau. */
		gt_copy(t[0], a);
		gt_sqr(t[1], a);
		gt_frb(q, a, k / 3);
		gt_inv(q, q);
		gt_mul(t[3], a, q);
		gt_mul(t[2], a, t[3]);
		gt_sqr(t[4], t[3]);
		gt_frb(q, t[2], k / 3);
		gt_inv(q, q);
		gt_mul(t[5], t[2], q);
		for (int i = 6; i < 6 * h; i++) {
			gt_frb(t[i], t[i - 6], 1);
		}

		/* Horner's rule in base 3: digit d at position i is multiplied by
		 * tau^i = (-w)^m * 3^m * tau^(i - 2m) for m = i / 2, and the unit
		 * (-w)^m only changes the unit of the digit. */
		gt_set_unity(c);
		for (int m = ((int)l - 1) / 2; m >= 0 && l > 0; m--) {
			if (!first) {
				RLC_CAT(RLC_GT_LOWER, cub_cyc)(c, c);
			}
			for (int i = 2 * m; i < RLC_MIN(2 * m + 2, (int)l); i++) {
				for (int e = 0; e < h; e++) {
					if (i >= (int)len[e] || naf[e][i] == 0) {
						continue;
					}
					d = naf[e][i] - 1;
					f = (d % 3 + m) % 3;
					j = 6 * e + d / 6 + 3 * (i - 2 * m);
					gt_frb(q, t[j], f * k / 3);
					if (((d % 6) / 3) ^ (m & 1)) {
						gt_inv(q, q);
					}
					if (first) {
						gt_copy(c, q);
						first = 0;
					} else {
						gt_mul(c, c, q);
					}
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, x, y);
		bn_free_all(r[0], r[1]);
		gt_free(q);
		for (int i = 0; i < 2 * h; i++) {
			bn_free(_b[i]);
		}
		for (int i = 0; i < 6 * h; i++) {
			gt_free(t[i]);
		}
		RLC_FREE(t);
	}
}

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void g1_mul(g1_t c, const g1_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		g1_mul_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			g1_neg(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G1_LOWER, mul)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g1_mul_gen(g1_t c, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G1_LOWER, mul_gen)(c, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul(g2_t c, const g2_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		g2_mul_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			g2_neg(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G2_LOWER, mul)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul_gen(g2_t c, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G2_LOWER, mul_gen)(c, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void gt_exp(gt_t c, const gt_t a, const bn_t b) {
	if (bn_bits(b) <= RLC_DIG) {
		gt_exp_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			gt_inv(c, c);
		}
		return;
	}

#if FP_PRIME == 1536 || FP_PRIME == 544
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		/* The exponentiation takes exponents up to the size of the field. */
		pc_get_ord(n);
		bn_mod(_b, b, n);
		RLC_CAT(RLC_GT_LOWER, exp_cyc)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
#elif FP_PRIME < 1536
	if (ep_curve_embed() == 18) {
		/* A variable-time GLS-SAC is actually faster due to shorter table. */
		gt_exp_gls_sac(c, a, b, 1, ep_curve_frdim());
	} else {
		gt_exp_gls_naf(c, a, b, NULL, NULL, ep_curve_frdim());
	}
#else
	RLC_CAT(RLC_GT_LOWER, exp)(c, a, b);
#endif
}

void gt_exp_twnaf(gt_t c, const gt_t a, const bn_t b) {
#if RLC_GT_EMBED % 6 == 0 && RLC_GT_EMBED <= 48
	switch (ep_curve_is_pairf()) {
		case EP_BN:
		case EP_B12:
		case EP_K18:
		case EP_B24:
		case EP_B48:
			/* The method pays off only when the power of Frobenius acting
			 * as w is direct, which fails in Fp^18 when the non-residue
			 * defining Fp^9 is not the generator of Fp^3. */
			if (ep_curve_embed() == RLC_GT_EMBED &&
					(RLC_GT_EMBED != 18 || fp3_field_get_cnr() == 0)) {
				gt_exp_tw_imp(c, a, b);
				return;
			}
			break;
		default:
			break;
	}
#endif
	gt_exp(c, a, b);
}

void gt_exp_sec(gt_t c, const gt_t a, const bn_t b) {
#if FP_PRIME < 1536 && FP_PRIME != 544
	size_t d = ep_curve_frdim();
	d = (d > 4 ? d / 4 : 1);
	/* The subscalars are split evenly into d groups. */
	while (ep_curve_frdim() % d != 0) {
		d++;
	}
	gt_exp_reg_sac(c, a, b, d, ep_curve_frdim());
#elif FP_PRIME == 1536 || FP_PRIME == 544
	/* There is no decomposition for these curves. */
	gt_exp_reg_gls(c, a, b, 1);
#else
	RLC_CAT(RLC_GT_LOWER, exp_monty)(c, a, b);
#endif
}

void gt_exp_dig(gt_t c, const gt_t a, dig_t b) {
	gt_t s, t;
	bn_t _b;
	int8_t u, naf[RLC_DIG + 1];
	size_t l;

	if (b == 0) {
		gt_set_unity(c);
		return;
	}

	gt_null(s);
	gt_null(t);
	bn_null(_b);

	RLC_TRY {
		gt_new(s);
		gt_new(t);
		bn_new(_b);

		bn_set_dig(_b, b);

		l = RLC_DIG + 1;
		bn_rec_naf(naf, &l, _b, 2);

		gt_inv(s, a);
		gt_copy(t, a);
		for (int i = l - 2; i >= 0; i--) {
			gt_sqr(t, t);
			u = naf[i];
			if (u > 0) {
				gt_mul(t, t, a);
			} else if (u < 0) {
				gt_mul(t, t, s);
			}
		}

		gt_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		gt_free(s);
		gt_free(t);
		bn_free(_b);
	}
}

void gt_exp_sim(gt_t e, const gt_t a, const bn_t b, const gt_t c, const bn_t d) {
	if (bn_is_zero(b)) {
		return gt_exp(e, c, d);
	}

	if (bn_is_zero(d)) {
		return gt_exp(e, a, b);
	}

#if FP_PRIME == 1536 || FP_PRIME == 544
	bn_t n, _b, _d;

	bn_null_all(n, _b, _d);

	RLC_TRY {
		bn_new_all(n, _b, _d);

		gt_get_ord(n);
		bn_mod(_b, b, n);
		bn_mod(_d, d, n);
		RLC_CAT(RLC_GT_LOWER, exp_cyc_sim)(e, a, _b, c, _d);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free_all(n, _b, _d);
	}
#elif FP_PRIME < 1536
	gt_exp_gls_naf(e, a, b, c, d, ep_curve_frdim());
#else
	gt_t t;

	gt_null(t);

	RLC_TRY {
		gt_new(t);

		gt_exp(t, a, b);
		gt_exp(e, c, d);
		gt_mul(e, e, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		gt_free(t);
	}
#endif
}

void gt_exp_gen(gt_t c, const bn_t b) {
	gt_t g;

	gt_null(g);

	RLC_TRY {
		gt_new(g);

		gt_get_gen(g);
		gt_exp(c, g, b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		gt_free(g);
	}
}
