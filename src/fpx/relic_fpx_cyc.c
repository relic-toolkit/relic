/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
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
 * Implementation of exponentiation in cyclotomic subgroups of extensions
 * defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_conv_cyc(fp2_t c, const fp2_t a) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		/* t = a^{-1}. */
		fp2_inv(t, a);
		/* c = a^p. */
		fp2_inv_cyc(c, a);
		/* c = a^(p - 1). */
		fp2_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}
}

int fp2_test_cyc(const fp2_t a) {
	fp2_t t;
	int result = 0;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);
		fp2_inv_cyc(t, a);
		fp2_mul(t, t, a);
		result = ((fp2_cmp_dig(t, 1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t);
	}

	return result;
}

void fp2_exp_cyc(fp2_t c, const fp2_t a, const bn_t b) {
	fp2_t r, s, t[1 << (RLC_WIDTH - 2)];
	int8_t naf[RLC_FP_BITS + 1], *k;
	size_t l;

	if (bn_is_zero(b)) {
		return fp2_set_dig(c, 1);
	}

	if (bn_bits(b) <= RLC_DIG) {
		fp2_exp_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			fp2_inv_cyc(c, c);
		}
		return;
	}

	fp2_null(r);
	fp2_null(s);

	RLC_TRY {
		fp2_new(r);
		fp2_new(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp2_null(t[i]);
			fp2_new(t[i]);
		}

#if RLC_WIDTH > 2
		fp2_sqr(t[0], a);
		fp2_mul(t[1], t[0], a);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_mul(t[i], t[i - 1], t[0]);
		}
#endif
		fp2_copy(t[0], a);

		l = RLC_FP_BITS + 1;
		fp2_set_dig(r, 1);
		bn_rec_naf(naf, &l, b, RLC_WIDTH);

		k = naf + l - 1;
		for (int i = l - 1; i >= 0; i--, k--) {
			fp2_sqr(r, r);

			if (*k > 0) {
				fp2_mul(r, r, t[*k / 2]);
			}
			if (*k < 0) {
				fp2_inv_cyc(s, t[-*k / 2]);
				fp2_mul(r, r, s);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp2_inv_cyc(c, r);
		} else {
			fp2_copy(c, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(r);
		fp2_free(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_free(t[i]);
		}
	}
}

void fp2_exp_cyc_sim(fp2_t e, const fp2_t a, const bn_t b, const fp2_t c,
		const bn_t d) {
	int n0, n1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *_k, *_m;
	fp2_t r, t0[1 << (RLC_WIDTH - 2)];
	fp2_t s, t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	if (bn_is_zero(b)) {
		return fp2_exp_cyc(e, c, d);
	}

	if (bn_is_zero(d)) {
		return fp2_exp_cyc(e, a, b);
	}

	fp2_null(r);
	fp2_null(s);

	RLC_TRY {
		fp2_new(r);
		fp2_new(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp2_null(t0[i]);
			fp2_null(t1[i]);
			fp2_new(t0[i]);
			fp2_new(t1[i]);
		}

#if RLC_WIDTH > 2
		fp2_sqr(t0[0], a);
		fp2_mul(t0[1], t0[0], a);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_mul(t0[i], t0[i - 1], t0[0]);
		}

		fp2_sqr(t1[0], c);
		fp2_mul(t1[1], t1[0], c);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_mul(t1[i], t1[i - 1], t1[0]);
		}
#endif
		fp2_copy(t0[0], a);
		fp2_copy(t1[0], c);

		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, b, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, d, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		if (bn_sign(b) == RLC_NEG) {
			for (size_t i = 0; i < l0; i++) {
				naf0[i] = -naf0[i];
			}
		}
		if (bn_sign(d) == RLC_NEG) {
			for (size_t i = 0; i < l1; i++) {
				naf1[i] = -naf1[i];
			}
		}

		_k = naf0 + l - 1;
		_m = naf1 + l - 1;

		fp2_set_dig(r, 1);
		for (int i = l - 1; i >= 0; i--, _k--, _m--) {
			fp2_sqr(r, r);

			n0 = *_k;
			n1 = *_m;

			if (n0 > 0) {
				fp2_mul(r, r, t0[n0 / 2]);
			}
			if (n0 < 0) {
				fp2_inv_cyc(s, t0[-n0 / 2]);
				fp2_mul(r, r, s);
			}
			if (n1 > 0) {
				fp2_mul(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				fp2_inv_cyc(s, t1[-n1 / 2]);
				fp2_mul(r, r, s);
			}
		}

		fp2_copy(e, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(r);
		fp2_free(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_free(t0[i]);
			fp2_free(t1[i]);
		}
	}
}

void fp8_conv_cyc(fp8_t c, const fp8_t a) {
	fp8_t t;

	fp8_null(t);

	RLC_TRY {
		fp8_new(t);

		/* t = a^{-1}. */
		fp8_inv(t, a);
		/* c = a^(p^4). */
		fp8_inv_cyc(c, a);
		/* c = a^(p^4 - 1). */
		fp8_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(t);
	}
}

int fp8_test_cyc(const fp8_t a) {
	fp8_t t;
	int result = 0;

	fp8_null(t);

	RLC_TRY {
		fp8_new(t);
		fp8_inv_cyc(t, a);
		fp8_mul(t, t, a);
		result = ((fp8_cmp_dig(t, 1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(t);
	}

	return result;
}

void fp8_exp_cyc(fp8_t c, const fp8_t a, const bn_t b) {
	fp8_t r, s, t[1 << (RLC_WIDTH - 2)];
	int8_t naf[RLC_FP_BITS + 1], *k, w = RLC_WIDTH;
	size_t l;

	if (bn_is_zero(b)) {
		return fp8_set_dig(c, 1);
	}

	if (bn_bits(b) <= RLC_DIG) {
		w = 2;
	}

	fp8_null(r);
	fp8_null(s);

	RLC_TRY {
		fp8_new(r);
		fp8_new(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp8_null(t[i]);
			fp8_new(t[i]);
		}

#if RLC_WIDTH > 2
		fp8_sqr_cyc(t[0], a);
		fp8_mul(t[1], t[0], a);
		for (int i = 2; i < (1 << (w - 2)); i++) {
			fp8_mul(t[i], t[i - 1], t[0]);
		}
#endif
		fp8_copy(t[0], a);

		l = RLC_FP_BITS + 1;
		fp8_set_dig(r, 1);
		bn_rec_naf(naf, &l, b, w);

		k = naf + l - 1;
		for (int i = l - 1; i >= 0; i--, k--) {
			fp8_sqr_cyc(r, r);

			if (*k > 0) {
				fp8_mul(r, r, t[*k / 2]);
			}
			if (*k < 0) {
				fp8_inv_cyc(s, t[-*k / 2]);
				fp8_mul(r, r, s);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp8_inv_cyc(c, r);
		} else {
			fp8_copy(c, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(r);
		fp8_free(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp8_free(t[i]);
		}
	}
}

void fp12_conv_cyc(fp12_t c, const fp12_t a) {
	fp12_t t;

	fp12_null(t);

	RLC_TRY {
		fp12_new(t);

		/* First, compute c = a^(p^6 - 1). */
		/* t = a^{-1}. */
		fp12_inv(t, a);
		/* c = a^(p^6). */
		fp12_inv_cyc(c, a);
		/* c = a^(p^6 - 1). */
		fp12_mul(c, c, t);

		/* Second, compute c^(p^2 + 1). */
		/* t = c^(p^2). */
		fp12_frb(t, c, 2);

		/* c = c^(p^2 + 1). */
		fp12_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(t);
	}
}

int fp12_test_cyc(const fp12_t a) {
	fp12_t t0, t1;
	int result = 0;

	fp12_null(t0);
	fp12_null(t1);

	RLC_TRY {
		fp12_new(t0);
		fp12_new(t1);

		/* Check if a^(p^4 - p^2 + 1) == 1. */
		fp12_frb(t0, a, 4);
		fp12_mul(t0, t0, a);
		fp12_frb(t1, a, 2);

		result = ((fp12_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(t0);
		fp12_free(t1);
	}

	return result;
}

void fp12_back_cyc(fp12_t c, const fp12_t a) {
	fp2_t t0, t1, t2;

	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);

		int f = fp2_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp2_copy(t2, a[0][1]);
		dv_copy_cond(t2[0], a[1][2][0], RLC_FP_DIGS, f);
		dv_copy_cond(t2[1], a[1][2][1], RLC_FP_DIGS, f);
		/* t0 = g4^2. */
		fp2_mul(t0, a[0][1], t2);
		fp2_dbl(t2, t0);
		dv_copy_cond(t0[0], t2[0], RLC_FP_DIGS, f);
		dv_copy_cond(t0[1], t2[1], RLC_FP_DIGS, f);
		/* t1 = 3 * g4^2 - 2 * g3. */
		fp2_sub(t1, t0, a[0][2]);
		fp2_dbl(t1, t1);
		fp2_add(t1, t1, t0);
		/* t0 = E * g5^2 + t1. */
		fp2_sqr(t2, a[1][2]);
		fp2_mul_nor(t0, t2);
		fp2_add(t0, t0, t1);
		/* t1 = (4 * g2). */
		fp2_dbl(t1, a[1][0]);
		fp2_dbl(t1, t1);
		dv_copy_cond(t1[0], a[0][2][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1], a[0][2][1], RLC_FP_DIGS, f);
		/* If unity, decompress to unity as well. */
		f = fp12_cmp_dig(a, 1) == RLC_EQ;
		fp2_set_dig(t2, 1);
		dv_copy_cond(t1[0], t2[0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1], t2[1], RLC_FP_DIGS, f);

		/* t1 = 1/g3 or 1/(4*g2), depending on the above. */
		fp2_inv(t1, t1);
		/* c_1 = g1. */
		fp2_mul(c[1][1], t0, t1);

		/* t1 = g3 * g4. */
		fp2_mul(t1, a[0][2], a[0][1]);
		/* t2 = 2 * g1^2 - 3 * g3 * g4. */
		fp2_sqr(t2, c[1][1]);
		fp2_sub(t2, t2, t1);
		fp2_dbl(t2, t2);
		fp2_sub(t2, t2, t1);
		/* t1 = g2 * g5. */
		fp2_mul(t1, a[1][0], a[1][2]);
		/* c_0 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
		fp2_add(t2, t2, t1);
		fp2_mul_nor(c[0][0], t2);
		fp_add_dig(c[0][0][0], c[0][0][0], 1);

		fp2_copy(c[0][1], a[0][1]);
		fp2_copy(c[0][2], a[0][2]);
		fp2_copy(c[1][0], a[1][0]);
		fp2_copy(c[1][2], a[1][2]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
	}
}

void fp12_back_cyc_sim(fp12_t c[], const fp12_t a[], int n) {
    fp2_t *t = RLC_ALLOCA(fp2_t, n * 3);
    fp2_t *t0 = t + 0 * n, *t1 = t + 1 * n, *t2 = t + 2 * n;

	if (n == 0) {
		RLC_FREE(t);
		return;
	}

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (int i = 0; i < n; i++) {
			fp2_null(t0[i]);
			fp2_null(t1[i]);
			fp2_null(t2[i]);
			fp2_new(t0[i]);
			fp2_new(t1[i]);
			fp2_new(t2[i]);
		}

		for (int i = 0; i < n; i++) {
			int f = fp2_is_zero(a[i][1][0]);
			/* If f, t0 = 2 * g4 * g5, t1 = g3. */
			fp2_copy(t2[i], a[i][0][1]);
			dv_copy_cond(t2[i][0], a[i][1][2][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][1], a[i][1][2][1], RLC_FP_DIGS, f);
			/* t0 = g4^2. */
			fp2_mul(t0[i], a[i][0][1], t2[i]);
			fp2_dbl(t2[i], t0[i]);
			dv_copy_cond(t0[i][0], t2[i][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][1], t2[i][1], RLC_FP_DIGS, f);
			/* t1 = 3 * g4^2 - 2 * g3. */
			fp2_sub(t1[i], t0[i], a[i][0][2]);
			fp2_dbl(t1[i], t1[i]);
			fp2_add(t1[i], t1[i], t0[i]);
			/* t0 = E * g5^2 + t1. */
			fp2_sqr(t2[i], a[i][1][2]);
			fp2_mul_nor(t0[i], t2[i]);
			fp2_add(t0[i], t0[i], t1[i]);
			/* t1 = (4 * g2). */
			fp2_dbl(t1[i], a[i][1][0]);
			fp2_dbl(t1[i], t1[i]);
			dv_copy_cond(t1[i][0], a[i][0][2][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1], a[i][0][2][1], RLC_FP_DIGS, f);
			/* If unity, decompress to unity as well. */
			f = (fp12_cmp_dig(a[i], 1) == RLC_EQ);
			fp2_set_dig(t2[i], 1);
			dv_copy_cond(t1[i][0], t2[i][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1], t2[i][1], RLC_FP_DIGS, f);
		}

		/* t1 = 1 / t1. */
		fp2_inv_sim(t1, t1, n);

		for (int i = 0; i < n; i++) {
			/* t0 = g1. */
			fp2_mul(c[i][1][1], t0[i], t1[i]);

			/* t1 = g3 * g4. */
			fp2_mul(t1[i], a[i][0][2], a[i][0][1]);
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */
			fp2_sqr(t2[i], c[i][1][1]);
			fp2_sub(t2[i], t2[i], t1[i]);
			fp2_dbl(t2[i], t2[i]);
			fp2_sub(t2[i], t2[i], t1[i]);
			/* t1 = g2 * g5. */
			fp2_mul(t1[i], a[i][1][0], a[i][1][2]);
			/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
			fp2_add(t2[i], t2[i], t1[i]);
			fp2_mul_nor(c[i][0][0], t2[i]);
			fp_add_dig(c[i][0][0][0], c[i][0][0][0], 1);

			fp2_copy(c[i][0][1], a[i][0][1]);
			fp2_copy(c[i][0][2], a[i][0][2]);
			fp2_copy(c[i][1][0], a[i][1][0]);
			fp2_copy(c[i][1][2], a[i][1][2]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (int i = 0; i < n; i++) {
			fp2_free(t0[i]);
			fp2_free(t1[i]);
			fp2_free(t2[i]);
		}
		RLC_FREE(t);
	}
}

void fp12_exp_cyc(fp12_t c, const fp12_t a, const bn_t b) {
	size_t j, k, l, w = bn_ham(b);

	if (bn_is_zero(b)) {
		return fp12_set_dig(c, 1);
	}

	if ((bn_bits(b) > RLC_DIG) && ((bn_ham(b) << 3) > bn_bits(b))) {
		fp12_t r, s, t[1 << (RLC_WIDTH - 2)];
		int8_t naf[RLC_FP_BITS + 1], *k, w = RLC_WIDTH;

		if (bn_bits(b) <= RLC_DIG) {
			w = 2;
		}

		fp12_null(r);
		fp12_null(s);

		RLC_TRY {
			fp12_new(r);
			fp12_new(s);
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
				fp12_null(t[i]);
				fp12_new(t[i]);
			}

#if RLC_WIDTH > 2
			fp12_sqr_cyc(t[0], a);
			fp12_mul(t[1], t[0], a);
			for (int i = 2; i < (1 << (w - 2)); i++) {
				fp12_mul(t[i], t[i - 1], t[0]);
			}
#endif
			fp12_copy(t[0], a);

			l = RLC_FP_BITS + 1;
			fp12_set_dig(r, 1);
			bn_rec_naf(naf, &l, b, w);

			k = naf + l - 1;
			for (int i = l - 1; i >= 0; i--, k--) {
				fp12_sqr_cyc(r, r);

				if (*k > 0) {
					fp12_mul(r, r, t[*k / 2]);
				}
				if (*k < 0) {
					fp12_inv_cyc(s, t[-*k / 2]);
					fp12_mul(r, r, s);
				}
			}

			if (bn_sign(b) == RLC_NEG) {
				fp12_inv_cyc(c, r);
			} else {
				fp12_copy(c, r);
			}
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp12_free(r);
			fp12_free(s);
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
				fp12_free(t[i]);
			}
		}
	} else {
		fp12_t t, *u = RLC_ALLOCA(fp12_t, w);

		fp12_null(t);

		RLC_TRY {
			if (u == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			for (int i = 0; i < w; i++) {
				fp12_null(u[i]);
				fp12_new(u[i]);
			}
			fp12_new(t);

			j = 0;
			fp12_copy(t, a);
			for (size_t i = 1; i < bn_bits(b); i++) {
				fp12_sqr_pck(t, t);
				if (bn_get_bit(b, i)) {
					fp12_copy(u[j++], t);
				}
			}

			if (!bn_is_even(b)) {
				j = 0;
				k = w - 1;
			} else {
				j = 1;
				k = w;
			}

			fp12_back_cyc_sim(u, u, k);

			if (!bn_is_even(b)) {
				fp12_copy(c, a);
			} else {
				fp12_copy(c, u[0]);
			}

			for (size_t i = j; i < k; i++) {
				fp12_mul(c, c, u[i]);
			}

			if (bn_sign(b) == RLC_NEG) {
				fp12_inv_cyc(c, c);
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			for (size_t i = 0; i < w; i++) {
				fp12_free(u[i]);
			}
			fp12_free(t);
			RLC_FREE(u);
		}
	}
}

void fp12_exp_cyc_gls(fp12_t c, const fp12_t a, const bn_t b) {
	size_t l, _l[4];
	int8_t naf[4][RLC_FP_BITS + 1];
	fp12_t t[4];
	bn_t _b[4], n, u;

	if (bn_is_zero(b)) {
		return fp12_set_dig(c, 1);
	}

	bn_null(n);
	bn_null(u);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (size_t i = 0; i < 4; i++) {
			bn_null(_b[i]);
			bn_new(_b[i]);
			fp12_null(t[i]);
			fp12_new(t[i]);
		}

		ep_curve_get_ord(n);
		fp_prime_get_par(u);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, 4, _b[0], u, n, ep_curve_is_pairf() == EP_BN);

		fp12_copy(t[0], a);
		fp12_frb(t[1], t[0], 1);
		fp12_frb(t[2], t[1], 1);
		fp12_frb(t[3], t[2], 1);

		l = 0;
		for (size_t i = 0; i < 4; i++) {
			if (bn_sign(_b[i]) == RLC_NEG) {
				fp12_inv_cyc(t[i], t[i]);
			}
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _b[i], 2);
			l = RLC_MAX(l, _l[i]);
		}

		fp12_set_dig(c, 1);
		for (int i = l - 1; i >= 0; i--) {
			fp12_sqr_cyc(c, c);
			for (size_t j = 0; j < 4; j++) {
				if (naf[j][i] > 0) {
					fp12_mul(c, c, t[j]);
				}
				if (naf[j][i] < 0) {
					fp12_inv_cyc(t[j], t[j]);
					fp12_mul(c, c, t[j]);
					fp12_inv_cyc(t[j], t[j]);
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
		for (size_t i = 0; i < 4; i++) {
			bn_free(_b[i]);
			fp12_free(t[i]);
		}
	}
}

void fp12_exp_cyc_sim(fp12_t e, const fp12_t a, const bn_t b, const fp12_t c,
		const bn_t d) {
	int i, j, l;
	bn_t _b[4], _d[4], n, x;
	fp12_t t[4], u[4];

	if (bn_is_zero(b)) {
		return fp12_exp_cyc(e, c, d);
	}

	if (bn_is_zero(d)) {
		return fp12_exp_cyc(e, a, b);
	}

	bn_null(n);
	bn_null(x);

	RLC_TRY {
		bn_new(n);
		bn_new(x);
		for (i = 0; i < 4; i++) {
			bn_null(_b[i]);
			bn_null(_d[i]);
			fp12_null(t[i]);
			fp12_null(u[i]);
			bn_new(_b[i]);
			bn_new(_d[i]);
			fp12_new(t[i]);
			fp12_new(u[i]);
		}

		ep_curve_get_ord(n);
		fp_prime_get_par(x);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, 4, _b[0], x, n, ep_curve_is_pairf() == EP_BN);
		bn_abs(_d[0], d);
		bn_mod(_d[0], _d[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_d[0], _d[0]);
		}
		bn_rec_frb(_d, 4, _d[0], x, n, ep_curve_is_pairf() == EP_BN);

		if (ep_curve_is_pairf() && ep_param_embed() == 12) {
			for (i = 0; i < 4; i++) {
				fp12_frb(t[i], a, i);
				fp12_frb(u[i], c, i);
				if (bn_sign(_b[i]) == RLC_NEG) {
					fp12_inv_cyc(t[i], t[i]);
				}
				if (bn_sign(_d[i]) == RLC_NEG) {
					fp12_inv_cyc(u[i], u[i]);
				}
			}

			l = RLC_MAX(bn_bits(_b[0]), bn_bits(_b[1]));
			l = RLC_MAX(l, RLC_MAX(bn_bits(_b[2]), bn_bits(_b[3])));
			l = RLC_MAX(l, RLC_MAX(bn_bits(_d[0]), bn_bits(_d[1])));
			l = RLC_MAX(l, RLC_MAX(bn_bits(_d[2]), bn_bits(_d[3])));

			fp12_set_dig(e, 1);
			for (i = l - 1; i >= 0; i--) {
				fp12_sqr_cyc(e, e);
				for (j = 0; j < 4; j++) {
					if (bn_get_bit(_b[j], i)) {
						fp12_mul(e, e, t[j]);
					}
					if (bn_get_bit(_d[j], i)) {
						fp12_mul(e, e, u[j]);
					}
				}
			}
		} else {
			if (bn_sign(b) == RLC_NEG) {
				fp12_inv_cyc(t[0], a);
			} else {
				fp12_copy(t[0], a);
			}
			if (bn_sign(d) == RLC_NEG) {
				fp12_inv_cyc(u[0], c);
			} else {
				fp12_copy(u[0], c);
			}

			fp12_set_dig(e, 1);
			l = RLC_MAX(bn_bits(b), bn_bits(d));
			for (i = l - 1; i >= 0; i--) {
				fp12_sqr_cyc(e, e);
				if (bn_get_bit(b, i)) {
					fp12_mul(e, e, t[0]);
				}
				if (bn_get_bit(d, i)) {
					fp12_mul(e, e, u[0]);
				}
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(x);
		for (i = 0; i < 4; i++) {
			bn_free(_b[i]);
			bn_free(_d[i]);
			fp12_free(t[i]);
			fp12_free(u[i]);
		}
	}
}

void fp12_exp_cyc_sps(fp12_t c, const fp12_t a, const int *b, size_t len,
		int sign) {
	size_t i, j, k, w = len;
    fp12_t t, *u = RLC_ALLOCA(fp12_t, w);

	if (len == 0) {
		RLC_FREE(u);
		fp12_set_dig(c, 1);
		return;
	}

	fp12_null(t);

	RLC_TRY {
		if (u == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < w; i++) {
			fp12_null(u[i]);
			fp12_new(u[i]);
		}
		fp12_new(t);

		fp12_copy(t, a);
		if (b[0] == 0) {
			for (j = 0, i = 1; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp12_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp12_inv_cyc(u[i - 1], t);
				} else {
					fp12_copy(u[i - 1], t);
				}
			}

			fp12_back_cyc_sim(u, u, w - 1);

			fp12_copy(c, a);
			for (i = 0; i < w - 1; i++) {
				fp12_mul(c, c, u[i]);
			}
		} else {
			for (j = 0, i = 0; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp12_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp12_inv_cyc(u[i], t);
				} else {
					fp12_copy(u[i], t);
				}
			}

			fp12_back_cyc_sim(u, u, w);

			fp12_copy(c, u[0]);
			for (i = 1; i < w; i++) {
				fp12_mul(c, c, u[i]);
			}
		}

		if (sign == RLC_NEG) {
			fp12_inv_cyc(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < w; i++) {
			fp12_free(u[i]);
		}
		fp12_free(t);
		RLC_FREE(u);
	}
}

void fp16_conv_cyc(fp16_t c, const fp16_t a) {
	fp16_t t;

	fp16_null(t);

	RLC_TRY {
		fp16_new(t);

		/* t = a^{-1}. */
		fp16_inv(t, a);
		/* c = a^(p^8). */
		fp16_inv_cyc(c, a);
		/* c = a^(p^8 - 1). */
		fp16_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(t);
	}
}

int fp16_test_cyc(const fp16_t a) {
	fp16_t t;
	int result = 0;

	fp16_null(t);

	RLC_TRY {
		fp16_new(t);
		fp16_inv_cyc(t, a);
		fp16_mul(t, t, a);
		result = ((fp16_cmp_dig(t, 1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(t);
	}

	return result;
}

static void fp16_gls(fp16_t c, const fp16_t a) {
	fp16_t b;

	fp16_null(b);

	RLC_TRY {
		fp16_new(b);

		switch (ep_curve_is_pairf()) {
			case EP_K16:
				/* u = (2*p^5 - p) mod r */
				fp16_frb(b, a, 1);
				fp16_frb(c, b, 4);
				fp16_sqr_cyc(c, c);
				fp16_inv_cyc(b, b);
				fp16_mul(c, c, b);
				break;
			case EP_N16:
				/* u = -p^5 mod r */
				fp16_frb(c, a, 5);
				fp16_inv_cyc(c, c);
				break;
			case EP_FM16:
				fp16_frb(c, a, 1);
				break;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(b);
	}
}

void fp16_exp_cyc(fp16_t c, const fp16_t a, const bn_t b) {
	size_t l, w = RLC_WIDTH;
	fp16_t r, s, t[1 << (RLC_WIDTH - 2)];
	int8_t naf[RLC_FP_BITS + 1], *k;

	if (bn_is_zero(b)) {
		return fp16_set_dig(c, 1);
	}

	if (bn_bits(b) <= RLC_DIG) {
		w = 2;
	}

	fp16_null(r);
	fp16_null(s);

	RLC_TRY {
		fp16_new(r);
		fp16_new(s);
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp16_null(t[i]);
			fp16_new(t[i]);
		}

#if RLC_WIDTH > 2
		fp16_sqr_cyc(t[0], a);
		fp16_mul(t[1], t[0], a);
		for (size_t i = 2; i < (1 << (w - 2)); i++) {
			fp16_mul(t[i], t[i - 1], t[0]);
		}
#endif
		fp16_copy(t[0], a);

		l = RLC_FP_BITS + 1;
		fp16_set_dig(r, 1);
		bn_rec_naf(naf, &l, b, w);

		k = naf + l - 1;
		for (int i = l - 1; i >= 0; i--, k--) {
			fp16_sqr_cyc(r, r);

			if (*k > 0) {
				fp16_mul(r, r, t[*k / 2]);
			}
			if (*k < 0) {
				fp16_inv_cyc(s, t[-*k / 2]);
				fp16_mul(r, r, s);
			}
		}

		if (bn_sign(b) == RLC_NEG) {
			fp16_inv_cyc(c, r);
		} else {
			fp16_copy(c, r);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(r);
		fp16_free(s);
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp16_free(t[i]);
		}
	}
}

void fp16_exp_cyc_gls(fp16_t c, const fp16_t a, const bn_t b) {
	size_t i, l, _l[8];
	int8_t naf[8][RLC_FP_BITS + 1];
	fp16_t t[8];
	bn_t _b[8], n, x;

	if (bn_is_zero(b)) {
		return fp16_set_dig(c, 1);
	}

	bn_null(n);
	bn_null(x);

	RLC_TRY {
		bn_new(n);
		bn_new(x);
		for (i = 0; i < 8; i++) {
			bn_null(_b[i]);
			bn_new(_b[i]);
			fp16_null(t[i]);
			fp16_new(t[i]);
		}

		ep_curve_get_ord(n);
		fp_prime_get_par(x);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, 8, _b[0], x, n, ep_curve_is_pairf() == EP_BN);

		fp16_copy(t[0], a);
		for (int i = 1; i < 8; i++) {
			fp16_gls(t[i], t[i - 1]);
		}

		l = 0;
		for (size_t i = 0; i < 8; i++) {
			if (bn_sign(_b[i]) == RLC_NEG) {
				fp16_inv_cyc(t[i], t[i]);
			}
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _b[i], 2);
			l = RLC_MAX(l, _l[i]);
		}

		fp16_set_dig(c, 1);
		for (int i = l - 1; i >= 0; i--) {
			fp16_sqr_cyc(c, c);
			for (size_t j = 0; j < 8; j++) {
				if (naf[j][i] > 0) {
					fp16_mul(c, c, t[j]);
				}
				if (naf[j][i] < 0) {
					fp16_inv_cyc(t[j], t[j]);
					fp16_mul(c, c, t[j]);
					fp16_inv_cyc(t[j], t[j]);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(x);
		for (size_t i = 0; i < 8; i++) {
			bn_free(_b[i]);
			fp16_free(t[i]);
		}
	}
}

void fp16_exp_cyc_sim(fp16_t e, const fp16_t a, const bn_t b, const fp16_t c,
		const bn_t d) {
	int n0, n1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *_k, *_m;
	fp16_t r, t0[1 << (RLC_WIDTH - 2)];
	fp16_t s, t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	if (bn_is_zero(b)) {
		return fp16_exp_cyc(e, c, d);
	}

	if (bn_is_zero(d)) {
		return fp16_exp_cyc(e, a, b);
	}

	fp16_null(r);
	fp16_null(s);

	RLC_TRY {
		fp16_new(r);
		fp16_new(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp16_null(t0[i]);
			fp16_null(t1[i]);
			fp16_new(t0[i]);
			fp16_new(t1[i]);
		}

#if RLC_WIDTH > 2
		fp16_sqr_cyc(t0[0], a);
		fp16_mul(t0[1], t0[0], a);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp16_mul(t0[i], t0[i - 1], t0[0]);
		}

		fp16_sqr_cyc(t1[0], c);
		fp16_mul(t1[1], t1[0], c);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp16_mul(t1[i], t1[i - 1], t1[0]);
		}
#endif
		fp16_copy(t0[0], a);
		fp16_copy(t1[0], c);

		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, b, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, d, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		if (bn_sign(b) == RLC_NEG) {
			for (size_t i = 0; i < l0; i++) {
				naf0[i] = -naf0[i];
			}
		}
		if (bn_sign(d) == RLC_NEG) {
			for (size_t i = 0; i < l1; i++) {
				naf1[i] = -naf1[i];
			}
		}

		_k = naf0 + l - 1;
		_m = naf1 + l - 1;

		fp16_set_dig(r, 1);
		for (int i = l - 1; i >= 0; i--, _k--, _m--) {
			fp16_sqr(r, r);

			n0 = *_k;
			n1 = *_m;

			if (n0 > 0) {
				fp16_mul(r, r, t0[n0 / 2]);
			}
			if (n0 < 0) {
				fp16_inv_cyc(s, t0[-n0 / 2]);
				fp16_mul(r, r, s);
			}
			if (n1 > 0) {
				fp16_mul(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				fp16_inv_cyc(s, t1[-n1 / 2]);
				fp16_mul(r, r, s);
			}
		}

		fp16_copy(e, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(r);
		fp16_free(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp16_free(t0[i]);
			fp16_free(t1[i]);
		}
	}
}

void fp18_conv_cyc(fp18_t c, const fp18_t a) {
	fp18_t t;

	fp18_null(t);

	RLC_TRY {
		fp18_new(t);

		/* First, compute c = a^(p^9 - 1). */
		/* t = a^{-1}. */
		fp18_inv(t, a);
		/* c = a^(p^9). */
		fp18_inv_cyc(c, a);
		/* c = a^(p^9 - 1). */
		fp18_mul(c, c, t);

		/* Second, compute c^(p^3 + 1). */
		/* t = c^(p^3). */
		fp18_frb(t, c, 3);

		/* c = c^(p^3 + 1). */
		fp18_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp18_free(t);
	}
}

int fp18_test_cyc(const fp18_t a) {
	fp18_t t0, t1;
	int result = 0;

	fp18_null(t0);
	fp18_null(t1);

	RLC_TRY {
		fp18_new(t0);
		fp18_new(t1);

		/* Check if a^(p^6 - p^3 + 1) == 1. */
		fp18_frb(t0, a, 6);
		fp18_mul(t0, t0, a);
		fp18_frb(t1, a, 3);

		result = ((fp18_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp18_free(t0);
		fp18_free(t1);
	}

	return result;
}

void fp18_back_cyc(fp18_t c, const fp18_t a) {
	fp3_t t0, t1, t2;

	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);

	RLC_TRY {
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);

		int f = fp3_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp3_copy(t2, a[0][1]);
		dv_copy_cond(t2[0], a[1][2][0], RLC_FP_DIGS, f);
		dv_copy_cond(t2[1], a[1][2][1], RLC_FP_DIGS, f);
		dv_copy_cond(t2[2], a[1][2][2], RLC_FP_DIGS, f);
		/* t0 = g4^2. */
		fp3_mul(t0, a[0][1], t2);
		fp3_dbl(t2, t0);
		dv_copy_cond(t0[0], t2[0], RLC_FP_DIGS, f);
		dv_copy_cond(t0[1], t2[1], RLC_FP_DIGS, f);
		dv_copy_cond(t0[2], t2[2], RLC_FP_DIGS, f);
		/* t1 = 3 * g4^2 - 2 * g3. */
		fp3_sub(t1, t0, a[0][2]);
		fp3_dbl(t1, t1);
		fp3_add(t1, t1, t0);
		/* t0 = E * g5^2 + t1. */
		fp3_sqr(t2, a[1][2]);
		fp3_mul_nor(t0, t2);
		fp3_add(t0, t0, t1);
		/* t1 = (4 * g2). */
		fp3_dbl(t1, a[1][0]);
		fp3_dbl(t1, t1);
		dv_copy_cond(t1[0], a[0][2][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1], a[0][2][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[2], a[0][2][2], RLC_FP_DIGS, f);
		/* If unity, decompress to unity as well. */
		f = fp18_cmp_dig(a, 1) == RLC_EQ;
		fp3_set_dig(t2, 1);
		dv_copy_cond(t1[0], t2[0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1], t2[1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[2], t2[2], RLC_FP_DIGS, f);

		/* t1 = 1/g3 or 1/(4 * g2), depending on the above. */
		fp3_inv(t1, t1);
		/* c_1 = g1. */
		fp3_mul(c[1][1], t0, t1);

		/* t1 = g3 * g4. */
		fp3_mul(t1, a[0][2], a[0][1]);
		/* t2 = 2 * g1^2 - 3 * g3 * g4. */
		fp3_sqr(t2, c[1][1]);
		fp3_sub(t2, t2, t1);
		fp3_dbl(t2, t2);
		fp3_sub(t2, t2, t1);
		/* t1 = g2 * g5. */
		fp3_mul(t1, a[1][0], a[1][2]);
		/* c_0 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
		fp3_add(t2, t2, t1);
		fp3_mul_nor(c[0][0], t2);
		fp_add_dig(c[0][0][0], c[0][0][0], 1);

		fp3_copy(c[0][1], a[0][1]);
		fp3_copy(c[0][2], a[0][2]);
		fp3_copy(c[1][0], a[1][0]);
		fp3_copy(c[1][2], a[1][2]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(t0);
		fp3_free(t1);
		fp3_free(t2);
	}
}

void fp18_back_cyc_sim(fp18_t c[], const fp18_t a[], int n) {
    fp3_t *t = RLC_ALLOCA(fp3_t, n * 3);
    fp3_t *t0 = t + 0 * n, *t1 = t + 1 * n, *t2 = t + 2 * n;

	if (n == 0) {
		RLC_FREE(t);
		return;
	}

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (int i = 0; i < n; i++) {
			fp3_null(t0[i]);
			fp3_null(t1[i]);
			fp3_null(t2[i]);
			fp3_new(t0[i]);
			fp3_new(t1[i]);
			fp3_new(t2[i]);
		}

		for (int i = 0; i < n; i++) {
			int f = fp3_is_zero(a[i][1][0]);
			/* If f, t0 = 2 * g4 * g5, t1 = g3. */
			fp3_copy(t2[i], a[i][0][1]);
			dv_copy_cond(t2[i][0], a[i][1][2][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][1], a[i][1][2][1], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][2], a[i][1][2][2], RLC_FP_DIGS, f);
			/* t0 = g4^2. */
			fp3_mul(t0[i], a[i][0][1], t2[i]);
			fp3_dbl(t2[i], t0[i]);
			dv_copy_cond(t0[i][0], t2[i][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][1], t2[i][1], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][2], t2[i][2], RLC_FP_DIGS, f);
			/* t1 = 3 * g4^2 - 2 * g3. */
			fp3_sub(t1[i], t0[i], a[i][0][2]);
			fp3_dbl(t1[i], t1[i]);
			fp3_add(t1[i], t1[i], t0[i]);
			/* t0 = E * g5^2 + t1. */
			fp3_sqr(t2[i], a[i][1][2]);
			fp3_mul_nor(t0[i], t2[i]);
			fp3_add(t0[i], t0[i], t1[i]);
			/* t1 = (4 * g2). */
			fp3_dbl(t1[i], a[i][1][0]);
			fp3_dbl(t1[i], t1[i]);
			dv_copy_cond(t1[i][0], a[i][0][2][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1], a[i][0][2][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][2], a[i][0][2][2], RLC_FP_DIGS, f);
			/* If unity, decompress to unity as well. */
			f = (fp18_cmp_dig(a[i], 1) == RLC_EQ);
			fp3_set_dig(t2[i], 1);
			dv_copy_cond(t1[i][0], t2[i][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1], t2[i][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][2], t2[i][2], RLC_FP_DIGS, f);
		}

		/* t1 = 1 / t1. */
		fp3_inv_sim(t1, t1, n);

		for (int i = 0; i < n; i++) {
			/* t0 = g1. */
			fp3_mul(c[i][1][1], t0[i], t1[i]);

			/* t1 = g3 * g4. */
			fp3_mul(t1[i], a[i][0][2], a[i][0][1]);
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */
			fp3_sqr(t2[i], c[i][1][1]);
			fp3_sub(t2[i], t2[i], t1[i]);
			fp3_dbl(t2[i], t2[i]);
			fp3_sub(t2[i], t2[i], t1[i]);
			/* t1 = g2 * g5. */
			fp3_mul(t1[i], a[i][1][0], a[i][1][2]);
			/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
			fp3_add(t2[i], t2[i], t1[i]);
			fp3_mul_nor(c[i][0][0], t2[i]);
			fp_add_dig(c[i][0][0][0], c[i][0][0][0], 1);

			fp3_copy(c[i][0][1], a[i][0][1]);
			fp3_copy(c[i][0][2], a[i][0][2]);
			fp3_copy(c[i][1][0], a[i][1][0]);
			fp3_copy(c[i][1][2], a[i][1][2]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (int i = 0; i < n; i++) {
			fp3_free(t0[i]);
			fp3_free(t1[i]);
			fp3_free(t2[i]);
		}
		RLC_FREE(t);
	}
}

static void fp18_gls(fp18_t c, const fp18_t a) {
	fp18_t b;

	fp18_null(b);

	RLC_TRY {
		fp18_new(b);

		switch (ep_curve_is_pairf()) {
			case EP_SG18:
				/* -3*u = (2*p^2 - p^5) mod r */
				fp18_frb(b, a, 5);
				fp18_inv_cyc(b, b);
				fp18_frb(c, a, 2);
				fp18_sqr_cyc(c, c);
				fp18_mul(c, c, b);
				break;
			case EP_K18:
				/* For KSS18, we have that x = p^4 - 3*p = (p^3 - 3)p mod n. */
				fp18_sqr_cyc(b, a);
				fp18_mul(b, b, a);
				fp18_frb(c, a, 3);
				fp18_inv_cyc(b, b);
				fp18_mul(c, c, b);
				fp18_frb(c, c, 1);
				break;
			case EP_FM18:
				/* For FM18, we have that u = (p^4-p) mod r. */
				fp18_frb(b, a, 3);
				fp18_inv_cyc(b, b);
				fp18_mul(c, a, b);
				fp18_frb(c, c, 1);
				fp18_inv_cyc(c, c);
				break;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp18_free(b);
	}
}

void fp18_exp_cyc(fp18_t c, const fp18_t a, const bn_t b) {
	size_t l, w = bn_ham(b);

	if (bn_is_zero(b)) {
		return fp18_set_dig(c, 1);
	}

	if ((bn_bits(b) > RLC_DIG) && ((w << 3) > bn_bits(b))) {
		fp18_t r, s, t[1 << (RLC_WIDTH - 2)];
		int8_t naf[RLC_FP_BITS + 1], *k;

		if (bn_bits(b) <= RLC_DIG) {
			w = 2;
		} else {
			w = RLC_WIDTH;
		}

		fp18_null(r);
		fp18_null(s);

		RLC_TRY {
			fp18_new(r);
			fp18_new(s);
			for (size_t i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
				fp18_null(t[i]);
				fp18_new(t[i]);
			}

#if RLC_WIDTH > 2
			fp18_sqr_cyc(t[0], a);
			fp18_mul(t[1], t[0], a);
			for (size_t i = 2; i < (1 << (w - 2)); i++) {
				fp18_mul(t[i], t[i - 1], t[0]);
			}
#endif
			fp18_copy(t[0], a);

			l = RLC_FP_BITS + 1;
			fp18_set_dig(r, 1);
			bn_rec_naf(naf, &l, b, w);

			k = naf + l - 1;
			for (int i = l - 1; i >= 0; i--, k--) {
				fp18_sqr_cyc(r, r);

				if (*k > 0) {
					fp18_mul(r, r, t[*k / 2]);
				}
				if (*k < 0) {
					fp18_inv_cyc(s, t[-*k / 2]);
					fp18_mul(r, r, s);
				}
			}

			if (bn_sign(b) == RLC_NEG) {
				fp18_inv_cyc(c, r);
			} else {
				fp18_copy(c, r);
			}
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp18_free(r);
			fp18_free(s);
			for (size_t i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
				fp18_free(t[i]);
			}
		}
	} else {
		size_t j, k;
		fp18_t t, *u = RLC_ALLOCA(fp18_t, w);

		fp18_null(t);

		RLC_TRY {
			if (u == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			for (int i = 0; i < w; i++) {
				fp18_null(u[i]);
				fp18_new(u[i]);
			}
			fp18_new(t);

			j = 0;
			fp18_copy(t, a);
			for (size_t i = 1; i < bn_bits(b); i++) {
				fp18_sqr_pck(t, t);
				if (bn_get_bit(b, i)) {
					fp18_copy(u[j++], t);
				}
			}

			if (!bn_is_even(b)) {
				j = 0;
				k = w - 1;
			} else {
				j = 1;
				k = w;
			}

			fp18_back_cyc_sim(u, u, k);

			if (!bn_is_even(b)) {
				fp18_copy(c, a);
			} else {
				fp18_copy(c, u[0]);
			}

			for (size_t i = j; i < k; i++) {
				fp18_mul(c, c, u[i]);
			}

			if (bn_sign(b) == RLC_NEG) {
				fp18_inv_cyc(c, c);
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			for (size_t i = 0; i < w; i++) {
				fp18_free(u[i]);
			}
			fp18_free(t);
			RLC_FREE(u);
		}
	}
}

void fp18_exp_cyc_gls(fp18_t c, const fp18_t a, const bn_t b) {
	size_t l, _l[6];
	int8_t naf[6][RLC_FP_BITS + 1];
	fp18_t t[6];
	bn_t _b[6], n, x;

	if (bn_is_zero(b)) {
		return fp18_set_dig(c, 1);
	}

	bn_null(n);
	bn_null(x);

	RLC_TRY {
		bn_new(n);
		bn_new(x);
		for (size_t i = 0; i < 6; i++) {
			bn_null(_b[i]);
			bn_new(_b[i]);
			fp18_null(t[i]);
			fp18_new(t[i]);
		}

		fp_prime_get_par(x);
		if (ep_curve_is_pairf() == EP_SG18) {
			/* Compute base -3*u for the recoding below. */
			bn_dbl(n, x);
			bn_add(x, x, n);
			bn_neg(x, x);
		}
		ep_curve_get_ord(n);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, 6, _b[0], x, n, ep_curve_is_pairf() == EP_BN);

		l = 0;
		fp18_copy(t[0], a);
		for (size_t i = 0; i < 6; i++) {
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _b[i], 2);
			l = RLC_MAX(l, _l[i]);
			if (i > 0) {
				fp18_gls(t[i], t[i - 1]);
			}
		}

		for (size_t i = 0; i < 6; i++) {
			if (bn_sign(_b[i]) == RLC_NEG) {
				fp18_inv_cyc(t[i], t[i]);
			}
		}

		fp18_set_dig(c, 1);
		for (int i = l - 1; i >= 0; i--) {
			fp18_sqr_cyc(c, c);
			for (int j = 0; j < 6; j++) {
				if (naf[j][i] > 0) {
					fp18_mul(c, c, t[j]);
				}
				if (naf[j][i] < 0) {
					fp18_inv_cyc(t[j], t[j]);
					fp18_mul(c, c, t[j]);
					fp18_inv_cyc(t[j], t[j]);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(x);
		for (size_t i = 0; i < 6; i++) {
			bn_free(_b[i]);
			fp18_free(t[i]);
		}
	}
}

void fp18_exp_cyc_sim(fp18_t e, const fp18_t a, const bn_t b, const fp18_t c,
		const bn_t d) {
	int i, n0, n1;
	size_t l, l0, l1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *_k, *_m;
	fp18_t r, t0[1 << (RLC_WIDTH - 2)];
	fp18_t s, t1[1 << (RLC_WIDTH - 2)];

	if (bn_is_zero(b)) {
		return fp18_exp_cyc(e, c, d);
	}

	if (bn_is_zero(d)) {
		return fp18_exp_cyc(e, a, b);
	}

	fp18_null(r);
	fp18_null(s);

	RLC_TRY {
		fp18_new(r);
		fp18_new(s);
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp18_null(t0[i]);
			fp18_null(t1[i]);
			fp18_new(t0[i]);
			fp18_new(t1[i]);
		}

#if RLC_WIDTH > 2
		fp18_sqr(t0[0], a);
		fp18_mul(t0[1], t0[0], a);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp18_mul(t0[i], t0[i - 1], t0[0]);
		}

		fp18_sqr(t1[0], c);
		fp18_mul(t1[1], t1[0], c);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp18_mul(t1[i], t1[i - 1], t1[0]);
		}
#endif
		fp18_copy(t0[0], a);
		fp18_copy(t1[0], c);

		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, b, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, d, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		if (bn_sign(b) == RLC_NEG) {
			for (i = 0; i < l0; i++) {
				naf0[i] = -naf0[i];
			}
		}
		if (bn_sign(d) == RLC_NEG) {
			for (i = 0; i < l1; i++) {
				naf1[i] = -naf1[i];
			}
		}

		_k = naf0 + l - 1;
		_m = naf1 + l - 1;

		fp18_set_dig(r, 1);
		for (i = l - 1; i >= 0; i--, _k--, _m--) {
			fp18_sqr(r, r);

			n0 = *_k;
			n1 = *_m;

			if (n0 > 0) {
				fp18_mul(r, r, t0[n0 / 2]);
			}
			if (n0 < 0) {
				fp18_inv_cyc(s, t0[-n0 / 2]);
				fp18_mul(r, r, s);
			}
			if (n1 > 0) {
				fp18_mul(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				fp18_inv_cyc(s, t1[-n1 / 2]);
				fp18_mul(r, r, s);
			}
		}

		fp18_copy(e, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp18_free(r);
		fp18_free(s);
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp18_free(t0[i]);
			fp18_free(t1[i]);
		}
	}
}

void fp18_exp_cyc_sps(fp18_t c, const fp18_t a, const int *b, int len,
		int sign) {
	int i, j, k, w = len;
    fp18_t t, *u = RLC_ALLOCA(fp18_t, w);

	if (len == 0) {
		RLC_FREE(u);
		fp18_set_dig(c, 1);
		return;
	}

	fp18_null(t);

	RLC_TRY {
		if (u == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < w; i++) {
			fp18_null(u[i]);
			fp18_new(u[i]);
		}
		fp18_new(t);

		fp18_copy(t, a);
		if (b[0] == 0) {
			for (j = 0, i = 1; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp18_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp18_inv_cyc(u[i - 1], t);
				} else {
					fp18_copy(u[i - 1], t);
				}
			}

			fp18_back_cyc_sim(u, u, w - 1);

			fp18_copy(c, a);
			for (i = 0; i < w - 1; i++) {
				fp18_mul(c, c, u[i]);
			}
		} else {
			for (j = 0, i = 0; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp18_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp18_inv_cyc(u[i], t);
				} else {
					fp18_copy(u[i], t);
				}
			}

			fp18_back_cyc_sim(u, u, w);

			fp18_copy(c, u[0]);
			for (i = 1; i < w; i++) {
				fp18_mul(c, c, u[i]);
			}
		}

		if (sign == RLC_NEG) {
			fp18_inv_cyc(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < w; i++) {
			fp18_free(u[i]);
		}
		fp18_free(t);
		RLC_FREE(u);
	}
}

void fp24_conv_cyc(fp24_t c, const fp24_t a) {
	fp24_t t;

	fp24_null(t);

	RLC_TRY {
		fp24_new(t);

		/* First, compute c = a^(p^18 - 1). */
		/* t = a^{-1}. */
		fp24_inv(t, a);
		/* c = a^(p^12). */
		fp24_inv_cyc(c, a);
		/* c = a^(p^12 - 1). */
		fp24_mul(c, c, t);

		/* Second, compute c^(p^4 + 1). */
		/* t = c^(p^4). */
		fp24_frb(t, c, 4);

		/* c = c^(p^4 + 1). */
		fp24_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp24_free(t);
	}
}

int fp24_test_cyc(const fp24_t a) {
	fp24_t t0, t1;
	int result = 0;

	fp24_null(t0);
	fp24_null(t1);

	RLC_TRY {
		fp24_new(t0);
		fp24_new(t1);

		/* Check if a^(p^8 - p^4 + 1) == 1. */
		fp24_frb(t0, a, 8);
		fp24_mul(t0, t0, a);
		fp24_frb(t1, a, 4);

		result = ((fp24_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp24_free(t0);
		fp24_free(t1);
	}

	return result;
}

void fp24_back_cyc(fp24_t c, const fp24_t a) {
	fp4_t t0, t1, t2;

	fp4_null(t0);
	fp4_null(t1);
	fp4_null(t2);

	RLC_TRY {
		fp4_new(t0);
		fp4_new(t1);
		fp4_new(t2);

		int f = fp4_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp4_copy(t2, a[2][0]);
		dv_copy_cond(t2[0][0], a[2][1][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t2[0][1], a[2][1][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t2[1][0], a[2][1][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t2[1][1], a[2][1][1][1], RLC_FP_DIGS, f);
		/* t0 = g4^2. */
		fp4_mul(t0, a[2][0], t2);
		fp4_dbl(t2, t0);
		dv_copy_cond(t0[0][0], t2[0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t0[0][1], t2[0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t0[1][0], t2[1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t0[1][1], t2[1][1], RLC_FP_DIGS, f);
		/* t1 = 3 * g4^2 - 2 * g3. */
		fp4_sub(t1, t0, a[1][1]);
		fp4_dbl(t1, t1);
		fp4_add(t1, t1, t0);
		/* t0 = E * g5^2 + t1. */
		fp4_sqr(t2, a[2][1]);
		fp4_mul_art(t0, t2);
		fp4_add(t0, t0, t1);
		/* t1 = (4 * g2). */
		fp4_dbl(t1, a[1][0]);
		fp4_dbl(t1, t1);
		dv_copy_cond(t1[0][0], a[1][1][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[0][1], a[1][1][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][0], a[1][1][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][1], a[1][1][1][1], RLC_FP_DIGS, f);
		/* If unity, decompress to unity as well. */
		f = fp24_cmp_dig(a, 1) == RLC_EQ;
		fp4_set_dig(t2, 1);
		dv_copy_cond(t1[0][0], t2[0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[0][1], t2[0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][0], t2[1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][1], t2[1][1], RLC_FP_DIGS, f);

		fp4_inv(t1, t1);
		/* c_1 = g1. */
		fp4_mul(c[0][1], t0, t1);

		/* t1 = g3 * g4. */
		fp4_mul(t1, a[1][1], a[2][0]);
		/* t2 = 2 * g1^2 - 3 * g3 * g4. */
		fp4_sqr(t2, c[0][1]);
		fp4_sub(t2, t2, t1);
		fp4_dbl(t2, t2);
		fp4_sub(t2, t2, t1);
		/* t1 = g2 * g5. */
		fp4_mul(t1, a[1][0], a[2][1]);
		/* c_0 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
		fp4_add(t2, t2, t1);
		fp4_mul_art(c[0][0], t2);
		fp_add_dig(c[0][0][0][0], c[0][0][0][0], 1);

		fp4_copy(c[1][0], a[1][0]);
		fp4_copy(c[1][1], a[1][1]);
		fp4_copy(c[2][0], a[2][0]);
		fp4_copy(c[2][1], a[2][1]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(t0);
		fp4_free(t1);
		fp4_free(t2);
	}
}

void fp24_back_cyc_sim(fp24_t c[], const fp24_t a[], int n) {
    fp4_t *t = RLC_ALLOCA(fp4_t, n * 3);
    fp4_t *t0 = t + 0 * n, *t1 = t + 1 * n, *t2 = t + 2 * n;

	if (n == 0) {
		RLC_FREE(t);
		return;
	}

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (int i = 0; i < n; i++) {
			fp4_null(t0[i]);
			fp4_null(t1[i]);
			fp4_null(t2[i]);
			fp4_new(t0[i]);
			fp4_new(t1[i]);
			fp4_new(t2[i]);
		}

		for (int i = 0; i < n; i++) {
			int f = fp4_is_zero(a[i][1][0]);
			/* If f, t0 = 2 * g4 * g5, t1 = g3. */
			fp4_copy(t2[i], a[i][2][0]);
			dv_copy_cond(t2[i][0][0], a[i][2][1][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][0][1], a[i][2][1][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][1][0], a[i][2][1][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][1][1], a[i][2][1][1][1], RLC_FP_DIGS, f);
			/* t0 = g4^2. */
			fp4_mul(t0[i], a[i][2][0], t2[i]);
			fp4_dbl(t2[i], t0[i]);
			dv_copy_cond(t0[i][0][0], t2[i][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][0][1], t2[i][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][1][0], t2[i][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][1][1], t2[i][1][1], RLC_FP_DIGS, f);
			/* t1 = 3 * g4^2 - 2 * g3. */
			fp4_sub(t1[i], t0[i], a[i][1][1]);
			fp4_dbl(t1[i], t1[i]);
			fp4_add(t1[i], t1[i], t0[i]);
			/* t0 = E * g5^2 + t1. */
			fp4_sqr(t2[i], a[i][2][1]);
			fp4_mul_art(t0[i], t2[i]);
			fp4_add(t0[i], t0[i], t1[i]);
			/* t1 = (4 * g2). */
			fp4_dbl(t1[i], a[i][1][0]);
			fp4_dbl(t1[i], t1[i]);
			dv_copy_cond(t1[i][0][0], a[i][1][1][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][0][1], a[i][1][1][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][0], a[i][1][1][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][1], a[i][1][1][1][1], RLC_FP_DIGS, f);
			/* If unity, decompress to unity as well. */
			f = fp24_cmp_dig(a[i], 1) == RLC_EQ;
			fp4_set_dig(t2[i], 1);
			dv_copy_cond(t1[i][0][0], t2[i][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][0][1], t2[i][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][0], t2[i][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][1], t2[i][1][1], RLC_FP_DIGS, f);
		}

		/* t1 = 1 / t1. */
		fp4_inv_sim(t1, t1, n);

		for (int i = 0; i < n; i++) {
			/* t0 = g1. */
			fp4_mul(c[i][0][1], t0[i], t1[i]);

			/* t1 = g3 * g4. */
			fp4_mul(t1[i], a[i][1][1], a[i][2][0]);
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */
			fp4_sqr(t2[i], c[i][0][1]);
			fp4_sub(t2[i], t2[i], t1[i]);
			fp4_dbl(t2[i], t2[i]);
			fp4_sub(t2[i], t2[i], t1[i]);
			/* t1 = g2 * g5. */
			fp4_mul(t1[i], a[i][1][0], a[i][2][1]);
			/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
			fp4_add(t2[i], t2[i], t1[i]);
			fp4_mul_art(c[i][0][0], t2[i]);
			fp_add_dig(c[i][0][0][0][0], c[i][0][0][0][0], 1);

			fp4_copy(c[i][1][0], a[i][1][0]);
			fp4_copy(c[i][1][1], a[i][1][1]);
			fp4_copy(c[i][2][0], a[i][2][0]);
			fp4_copy(c[i][2][1], a[i][2][1]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (int i = 0; i < n; i++) {
			fp4_free(t0[i]);
			fp4_free(t1[i]);
			fp4_free(t2[i]);
		}
		RLC_FREE(t);
	}
}

void fp24_exp_cyc(fp24_t c, const fp24_t a, const bn_t b) {
	size_t l, w = bn_ham(b);

	if (bn_is_zero(b)) {
		return fp24_set_dig(c, 1);
	}

	if ((bn_bits(b) > RLC_DIG) && ((w << 3) > bn_bits(b))) {
		fp24_t r, s, t[1 << (RLC_WIDTH - 2)];
		int8_t naf[RLC_FP_BITS + 1], *k;

		if (bn_bits(b) <= RLC_DIG) {
			w = 2;
		} else {
			w = RLC_WIDTH;
		}

		fp24_null(r);
		fp24_null(s);

		RLC_TRY {
			fp24_new(r);
			fp24_new(s);
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
				fp24_null(t[i]);
				fp24_new(t[i]);
			}

#if RLC_WIDTH > 2
			fp24_sqr_cyc(t[0], a);
			fp24_mul(t[1], t[0], a);
			for (int i = 2; i < (1 << (w - 2)); i++) {
				fp24_mul(t[i], t[i - 1], t[0]);
			}
#endif
			fp24_copy(t[0], a);

			l = RLC_FP_BITS + 1;
			fp24_set_dig(r, 1);
			bn_rec_naf(naf, &l, b, w);

			k = naf + l - 1;
			for (int i = l - 1; i >= 0; i--, k--) {
				fp24_sqr_cyc(r, r);

				if (*k > 0) {
					fp24_mul(r, r, t[*k / 2]);
				}
				if (*k < 0) {
					fp24_inv_cyc(s, t[-*k / 2]);
					fp24_mul(r, r, s);
				}
			}

			if (bn_sign(b) == RLC_NEG) {
				fp24_inv_cyc(c, r);
			} else {
				fp24_copy(c, r);
			}
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp24_free(r);
			fp24_free(s);
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
				fp24_free(t[i]);
			}
		}
	} else {
		size_t j, k;
		fp24_t t, *u = RLC_ALLOCA(fp24_t, w);

		fp24_null(t);

		RLC_TRY {
			if (u == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			for (int i = 0; i < w; i++) {
				fp24_null(u[i]);
				fp24_new(u[i]);
			}
			fp24_new(t);

			j = 0;
			fp24_copy(t, a);
			for (size_t i = 1; i < bn_bits(b); i++) {
				fp24_sqr_pck(t, t);
				if (bn_get_bit(b, i)) {
					fp24_copy(u[j++], t);
				}
			}

			if (!bn_is_even(b)) {
				j = 0;
				k = w - 1;
			} else {
				j = 1;
				k = w;
			}

			fp24_back_cyc_sim(u, u, k);

			if (!bn_is_even(b)) {
				fp24_copy(c, a);
			} else {
				fp24_copy(c, u[0]);
			}

			for (size_t i = j; i < k; i++) {
				fp24_mul(c, c, u[i]);
			}

			if (bn_sign(b) == RLC_NEG) {
				fp24_inv_cyc(c, c);
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			for (size_t i = 0; i < w; i++) {
				fp24_free(u[i]);
			}
			fp24_free(t);
			RLC_FREE(u);
		}
	}
}

void fp24_exp_cyc_gls(fp24_t c, const fp24_t a, const bn_t b) {
	size_t l, _l[8];
	int8_t naf[8][RLC_FP_BITS + 1];
	fp24_t t[8];
	bn_t _b[8], n, x;

	if (bn_is_zero(b)) {
		fp24_set_dig(c, 1);
		return;
	}

	bn_null(n);
	bn_null(x);

	RLC_TRY {
		bn_new(n);
		bn_new(x);
		for (int i = 0; i < 8; i++) {
			bn_null(_b[i]);
			bn_new(_b[i]);
			fp24_null(t[i]);
			fp24_new(t[i]);
		}

		ep_curve_get_ord(n);
		fp_prime_get_par(x);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, 8, _b[0], x, n, ep_curve_is_pairf() == EP_BN);

		fp24_copy(t[0], a);
		for (size_t i = 1; i < 8; i++) {
			fp24_frb(t[i], t[i - 1], 1);
		}

		l = 0;
		for (size_t i = 0; i < 8; i++) {
			if (bn_sign(_b[i]) == RLC_NEG) {
				fp24_inv_cyc(t[i], t[i]);
			}
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _b[i], 2);
			l = RLC_MAX(l, _l[i]);
		}

		fp24_set_dig(c, 1);
		for (int i = l - 1; i >= 0; i--) {
			fp24_sqr_cyc(c, c);
			for (size_t j = 0; j < 8; j++) {
				if (naf[j][i] > 0) {
					fp24_mul(c, c, t[j]);
				}
				if (naf[j][i] < 0) {
					fp24_inv_cyc(t[j], t[j]);
					fp24_mul(c, c, t[j]);
					fp24_inv_cyc(t[j], t[j]);
				}
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(x);
		for (size_t i = 0; i < 8; i++) {
			bn_free(_b[i]);
			fp24_free(t[i]);
		}
	}
}

void fp24_exp_cyc_sim(fp24_t e, const fp24_t a, const bn_t b, const fp24_t c,
		const bn_t d) {
	int n0, n1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *_k, *_m;
	fp24_t r, t0[1 << (RLC_WIDTH - 2)];
	fp24_t s, t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	if (bn_is_zero(b)) {
		return fp24_exp_cyc(e, c, d);
	}

	if (bn_is_zero(d)) {
		return fp24_exp_cyc(e, a, b);
	}

	fp24_null(r);
	fp24_null(s);

	RLC_TRY {
		fp24_new(r);
		fp24_new(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp24_null(t0[i]);
			fp24_null(t1[i]);
			fp24_new(t0[i]);
			fp24_new(t1[i]);
		}

#if RLC_WIDTH > 2
		fp24_sqr(t0[0], a);
		fp24_mul(t0[1], t0[0], a);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp24_mul(t0[i], t0[i - 1], t0[0]);
		}

		fp24_sqr(t1[0], c);
		fp24_mul(t1[1], t1[0], c);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp24_mul(t1[i], t1[i - 1], t1[0]);
		}
#endif
		fp24_copy(t0[0], a);
		fp24_copy(t1[0], c);

		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, b, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, d, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		if (bn_sign(b) == RLC_NEG) {
			for (size_t i = 0; i < l0; i++) {
				naf0[i] = -naf0[i];
			}
		}
		if (bn_sign(d) == RLC_NEG) {
			for (size_t i = 0; i < l1; i++) {
				naf1[i] = -naf1[i];
			}
		}

		_k = naf0 + l - 1;
		_m = naf1 + l - 1;

		fp24_set_dig(r, 1);
		for (int i = l - 1; i >= 0; i--, _k--, _m--) {
			fp24_sqr(r, r);

			n0 = *_k;
			n1 = *_m;

			if (n0 > 0) {
				fp24_mul(r, r, t0[n0 / 2]);
			}
			if (n0 < 0) {
				fp24_inv_cyc(s, t0[-n0 / 2]);
				fp24_mul(r, r, s);
			}
			if (n1 > 0) {
				fp24_mul(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				fp24_inv_cyc(s, t1[-n1 / 2]);
				fp24_mul(r, r, s);
			}
		}

		fp24_copy(e, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp24_free(r);
		fp24_free(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp24_free(t0[i]);
			fp24_free(t1[i]);
		}
	}
}

void fp24_exp_cyc_sps(fp24_t c, const fp24_t a, const int *b, size_t len,
		int sign) {
	size_t i, j, k, w = len;
    fp24_t t, *u = RLC_ALLOCA(fp24_t, w);

	if (len == 0) {
		RLC_FREE(u);
		fp24_set_dig(c, 1);
		return;
	}

	fp24_null(t);

	RLC_TRY {
		if (u == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < w; i++) {
			fp24_null(u[i]);
			fp24_new(u[i]);
		}
		fp24_new(t);

		fp24_copy(t, a);
		if (b[0] == 0) {
			for (j = 0, i = 1; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp24_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp24_inv_cyc(u[i - 1], t);
				} else {
					fp24_copy(u[i - 1], t);
				}
			}

			fp24_back_cyc_sim(u, u, w - 1);

			fp24_copy(c, a);
			for (i = 0; i < w - 1; i++) {
				fp24_mul(c, c, u[i]);
			}
		} else {
			for (j = 0, i = 0; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp24_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp24_inv_cyc(u[i], t);
				} else {
					fp24_copy(u[i], t);
				}
			}

			fp24_back_cyc_sim(u, u, w);

			fp24_copy(c, u[0]);
			for (i = 1; i < w; i++) {
				fp24_mul(c, c, u[i]);
			}
		}

		if (sign == RLC_NEG) {
			fp24_inv_cyc(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < w; i++) {
			fp24_free(u[i]);
		}
		fp24_free(t);
		RLC_FREE(u);
	}
}

void fp48_conv_cyc(fp48_t c, const fp48_t a) {
	fp48_t t;

	fp48_null(t);

	RLC_TRY {
		fp48_new(t);

		/* First, compute c = a^(p^24 - 1). */
		/* t = a^{-1}. */
		fp48_inv(t, a);
		/* c = a^(p^24). */
		fp48_inv_cyc(c, a);
		/* c = a^(p^24 - 1). */
		fp48_mul(c, c, t);

		/* Second, compute c^(p^8 + 1). */
		/* t = c^(p^8). */
		fp48_frb(t, c, 8);

		/* c = c^(p^8 + 1). */
		fp48_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp48_free(t);
	}
}

int fp48_test_cyc(const fp48_t a) {
	fp48_t t0, t1;
	int result = 0;

	fp48_null(t0);
	fp48_null(t1);

	RLC_TRY {
		fp48_new(t0);
		fp48_new(t1);

		/* Check if a^(p^16 - p^8 + 1) == 1. */
		fp48_frb(t0, a, 16);
		fp48_mul(t0, t0, a);
		fp48_frb(t1, a, 8);

		result = ((fp48_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp48_free(t0);
		fp48_free(t1);
	}

	return result;
}

void fp48_back_cyc(fp48_t c, const fp48_t a) {
	fp8_t t0, t1, t2;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);

	RLC_TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);

		int f = fp8_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp8_copy(t2, a[0][1]);
		dv_copy_cond(t2[0][0][0], a[1][2][0][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t2[0][0][1], a[1][2][0][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t2[0][1][0], a[1][2][0][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t2[0][1][1], a[1][2][0][1][1], RLC_FP_DIGS, f);
		dv_copy_cond(t2[1][0][0], a[1][2][1][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t2[1][0][1], a[1][2][1][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t2[1][1][0], a[1][2][1][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t2[1][1][1], a[1][2][1][1][1], RLC_FP_DIGS, f);
		/* t0 = g4^2. */
		fp8_mul(t0, a[0][1], t2);
		fp8_dbl(t2, t0);
		dv_copy_cond(t0[0][0][0], t2[0][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t0[0][0][1], t2[0][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t0[0][1][0], t2[0][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t0[0][1][1], t2[0][1][1], RLC_FP_DIGS, f);
		dv_copy_cond(t0[1][0][0], t2[1][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t0[1][0][1], t2[1][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t0[1][1][0], t2[1][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t0[1][1][1], t2[1][1][1], RLC_FP_DIGS, f);
		/* t1 = 3 * g4^2 - 2 * g3. */
		fp8_sub(t1, t0, a[0][2]);
		fp8_dbl(t1, t1);
		fp8_add(t1, t1, t0);
		/* t0 = E * g5^2 + t1. */
		fp8_sqr(t2, a[1][2]);
		fp8_mul_art(t0, t2);
		fp8_add(t0, t0, t1);
		/* t1 = (4 * g2). */
		fp8_dbl(t1, a[1][0]);
		fp8_dbl(t1, t1);
		dv_copy_cond(t1[0][0][0], a[0][2][0][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[0][0][1], a[0][2][0][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[0][1][0], a[0][2][0][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[0][1][1], a[0][2][0][1][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][0][0], a[0][2][1][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][0][1], a[0][2][1][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][1][0], a[0][2][1][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][1][1], a[0][2][1][1][1], RLC_FP_DIGS, f);
		/* If unity, decompress to unity as well. */
		f = fp48_cmp_dig(a, 1) == RLC_EQ;
		fp8_set_dig(t2, 1);
		dv_copy_cond(t1[0][0][0], t2[0][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[0][0][1], t2[0][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[0][1][0], t2[0][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[0][1][1], t2[0][1][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][0][0], t2[1][0][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][0][1], t2[1][0][1], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][1][0], t2[1][1][0], RLC_FP_DIGS, f);
		dv_copy_cond(t1[1][1][1], t2[1][1][1], RLC_FP_DIGS, f);

		/* t1 = 1/g3 or 1/(4 * g2), depending on the above. */
		fp8_inv(t1, t1);
		/* c_1 = g1. */
		fp8_mul(c[1][1], t0, t1);

		/* t1 = g3 * g4. */
		fp8_mul(t1, a[0][2], a[0][1]);
		/* t2 = 2 * g1^2 - 3 * g3 * g4. */
		fp8_sqr(t2, c[1][1]);
		fp8_sub(t2, t2, t1);
		fp8_dbl(t2, t2);
		fp8_sub(t2, t2, t1);
		/* t1 = g2 * g5. */
		fp8_mul(t1, a[1][0], a[1][2]);
		/* c_0 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
		fp8_add(t2, t2, t1);
		fp8_mul_art(c[0][0], t2);
		fp_add_dig(c[0][0][0][0][0], c[0][0][0][0][0], 1);

		fp8_copy(c[0][1], a[0][1]);
		fp8_copy(c[0][2], a[0][2]);
		fp8_copy(c[1][0], a[1][0]);
		fp8_copy(c[1][2], a[1][2]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
	}
}

void fp48_back_cyc_sim(fp48_t c[], const fp48_t a[], int n) {
    fp8_t *t = RLC_ALLOCA(fp8_t, n * 3);
    fp8_t *t0 = t + 0 * n, *t1 = t + 1 * n, *t2 = t + 2 * n;

	if (n == 0) {
		RLC_FREE(t);
		return;
	}

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (int i = 0; i < n; i++) {
			fp8_null(t0[i]);
			fp8_null(t1[i]);
			fp8_null(t2[i]);
			fp8_new(t0[i]);
			fp8_new(t1[i]);
			fp8_new(t2[i]);
		}

		for (int i = 0; i < n; i++) {
			int f = fp8_is_zero(a[i][1][0]);
			/* If f, t0[i] = 2 * g4 * g5, t1[i] = g3. */
			fp8_copy(t2[i], a[i][0][1]);
			dv_copy_cond(t2[i][0][0][0], a[i][1][2][0][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][0][0][1], a[i][1][2][0][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][0][1][0], a[i][1][2][0][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][0][1][1], a[i][1][2][0][1][1], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][1][0][0], a[i][1][2][1][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][1][0][1], a[i][1][2][1][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][1][1][0], a[i][1][2][1][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[i][1][1][1], a[i][1][2][1][1][1], RLC_FP_DIGS, f);
			/* t0[i] = g4^2. */
			fp8_mul(t0[i], a[i][0][1], t2[i]);
			fp8_dbl(t2[i], t0[i]);
			dv_copy_cond(t0[i][0][0][0], t2[i][0][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][0][0][1], t2[i][0][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][0][1][0], t2[i][0][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][0][1][1], t2[i][0][1][1], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][1][0][0], t2[i][1][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][1][0][1], t2[i][1][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][1][1][0], t2[i][1][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[i][1][1][1], t2[i][1][1][1], RLC_FP_DIGS, f);
			/* t1[i] = 3 * g4^2 - 2 * g3. */
			fp8_sub(t1[i], t0[i], a[i][0][2]);
			fp8_dbl(t1[i], t1[i]);
			fp8_add(t1[i], t1[i], t0[i]);
			/* t0[i] = E * g5^2 + t1[i]. */
			fp8_sqr(t2[i], a[i][1][2]);
			fp8_mul_art(t0[i], t2[i]);
			fp8_add(t0[i], t0[i], t1[i]);
			/* t1[i] = (4 * g2). */
			fp8_dbl(t1[i], a[i][1][0]);
			fp8_dbl(t1[i], t1[i]);
			dv_copy_cond(t1[i][0][0][0], a[i][0][2][0][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][0][0][1], a[i][0][2][0][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][0][1][0], a[i][0][2][0][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][0][1][1], a[i][0][2][0][1][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][0][0], a[i][0][2][1][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][0][1], a[i][0][2][1][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][1][0], a[i][0][2][1][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][1][1], a[i][0][2][1][1][1], RLC_FP_DIGS, f);
			/* If unity, decompress to unity as well. */
			f = fp48_cmp_dig(a[i], 1) == RLC_EQ;
			fp8_set_dig(t2[i], 1);
			dv_copy_cond(t1[i][0][0][0], t2[i][0][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][0][0][1], t2[i][0][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][0][1][0], t2[i][0][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][0][1][1], t2[i][0][1][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][0][0], t2[i][1][0][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][0][1], t2[i][1][0][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][1][0], t2[i][1][1][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[i][1][1][1], t2[i][1][1][1], RLC_FP_DIGS, f);
		}

		/* t1 = 1 / t1. */
		fp8_inv_sim(t1, t1, n);

		for (int i = 0; i < n; i++) {
			/* t0 = g1. */
			fp8_mul(c[i][1][1], t0[i], t1[i]);

			/* t1 = g3 * g4. */
			fp8_mul(t1[i], a[i][0][2], a[i][0][1]);
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */
			fp8_sqr(t2[i], c[i][1][1]);
			fp8_sub(t2[i], t2[i], t1[i]);
			fp8_dbl(t2[i], t2[i]);
			fp8_sub(t2[i], t2[i], t1[i]);
			/* t1 = g2 * g5. */
			fp8_mul(t1[i], a[i][1][0], a[i][1][2]);
			/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
			fp8_add(t2[i], t2[i], t1[i]);
			fp8_mul_art(c[i][0][0], t2[i]);
			fp_add_dig(c[i][0][0][0][0][0], c[i][0][0][0][0][0], 1);

			fp8_copy(c[i][0][1], a[i][0][1]);
			fp8_copy(c[i][0][2], a[i][0][2]);
			fp8_copy(c[i][1][0], a[i][1][0]);
			fp8_copy(c[i][1][2], a[i][1][2]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (int i = 0; i < n; i++) {
			fp8_free(t0[i]);
			fp8_free(t1[i]);
			fp8_free(t2[i]);
		}
		RLC_FREE(t);
	}
}

void fp48_exp_cyc(fp48_t c, const fp48_t a, const bn_t b) {
	size_t l, w = bn_ham(b);

	if (bn_is_zero(b)) {
		return fp48_set_dig(c, 1);
	}

	if ((bn_bits(b) > RLC_DIG) && ((w << 3) > bn_bits(b))) {
		fp48_t r, s, t[1 << (RLC_WIDTH - 2)];
		int8_t naf[RLC_FP_BITS + 1], *k;

		if (bn_bits(b) <= RLC_DIG) {
			w = 2;
		} else {
			w = RLC_WIDTH;
		}

		fp48_null(r);
		fp48_null(s);

		RLC_TRY {
			fp48_new(r);
			fp48_new(s);
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
				fp48_null(t[i]);
				fp48_new(t[i]);
			}

#if RLC_WIDTH > 2
			fp48_sqr_cyc(t[0], a);
			fp48_mul(t[1], t[0], a);
			for (int i = 2; i < (1 << (w - 2)); i++) {
				fp48_mul(t[i], t[i - 1], t[0]);
			}
#endif
			fp48_copy(t[0], a);

			l = RLC_FP_BITS + 1;
			fp48_set_dig(r, 1);
			bn_rec_naf(naf, &l, b, w);

			k = naf + l - 1;
			for (int i = l - 1; i >= 0; i--, k--) {
				fp48_sqr_cyc(r, r);

				if (*k > 0) {
					fp48_mul(r, r, t[*k / 2]);
				}
				if (*k < 0) {
					fp48_inv_cyc(s, t[-*k / 2]);
					fp48_mul(r, r, s);
				}
			}

			if (bn_sign(b) == RLC_NEG) {
				fp48_inv_cyc(c, r);
			} else {
				fp48_copy(c, r);
			}
		} RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp48_free(r);
			fp48_free(s);
			for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
				fp48_free(t[i]);
			}
		}
	} else {
		size_t j, k;
		fp48_t t, *u = RLC_ALLOCA(fp48_t, w);

		fp48_null(t);

		RLC_TRY {
			if (u == NULL) {
				RLC_THROW(ERR_NO_MEMORY);
			}
			for (int i = 0; i < w; i++) {
				fp48_null(u[i]);
				fp48_new(u[i]);
			}
			fp48_new(t);

			j = 0;
			fp48_copy(t, a);
			for (size_t i = 1; i < bn_bits(b); i++) {
				fp48_sqr_pck(t, t);
				if (bn_get_bit(b, i)) {
					fp48_copy(u[j++], t);
				}
			}

			if (!bn_is_even(b)) {
				j = 0;
				k = w - 1;
			} else {
				j = 1;
				k = w;
			}

			fp48_back_cyc_sim(u, u, k);

			if (!bn_is_even(b)) {
				fp48_copy(c, a);
			} else {
				fp48_copy(c, u[0]);
			}

			for (size_t i = j; i < k; i++) {
				fp48_mul(c, c, u[i]);
			}

			if (bn_sign(b) == RLC_NEG) {
				fp48_inv_cyc(c, c);
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			for (size_t i = 0; i < w; i++) {
				fp48_free(u[i]);
			}
			fp48_free(t);
			RLC_FREE(u);
		}
	}
}

void fp48_exp_cyc_gls(fp48_t c, const fp48_t a, const bn_t b) {
	size_t l, _l[16];
	int8_t naf[16][RLC_FP_BITS + 1];
	fp48_t t[16];
	bn_t _b[16], n, x;

	if (bn_is_zero(b)) {
		fp48_set_dig(c, 1);
		return;
	}

	bn_null(n);
	bn_null(x);

	RLC_TRY {
		bn_new(n);
		bn_new(x);
		for (int i = 0; i < 8; i++) {
			bn_null(_b[i]);
			bn_new(_b[i]);
			fp48_null(t[i]);
			fp48_new(t[i]);
		}

		ep_curve_get_ord(n);
		fp_prime_get_par(x);
		bn_abs(_b[0], b);
		bn_mod(_b[0], _b[0], n);
		if (bn_sign(b) == RLC_NEG) {
			bn_neg(_b[0], _b[0]);
		}
		bn_rec_frb(_b, 16, _b[0], x, n, ep_curve_is_pairf() == EP_BN);

		fp48_copy(t[0], a);
		for (size_t i = 1; i < 16; i++) {
			fp48_frb(t[i], t[i - 1], 1);
		}

		l = 0;
		for (size_t i = 0; i < 16; i++) {
			if (bn_sign(_b[i]) == RLC_NEG) {
				fp48_inv_cyc(t[i], t[i]);
			}
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _b[i], 2);
			l = RLC_MAX(l, _l[i]);
		}

		fp48_set_dig(c, 1);
		for (int i = l - 1; i >= 0; i--) {
			fp48_sqr_cyc(c, c);
			for (size_t j = 0; j < 16; j++) {
				if (naf[j][i] > 0) {
					fp48_mul(c, c, t[j]);
				}
				if (naf[j][i] < 0) {
					fp48_inv_cyc(t[j], t[j]);
					fp48_mul(c, c, t[j]);
					fp48_inv_cyc(t[j], t[j]);
				}
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(x);
		for (size_t i = 0; i < 16; i++) {
			bn_free(_b[i]);
			fp48_free(t[i]);
		}
	}
}

void fp48_exp_cyc_sim(fp48_t e, const fp48_t a, const bn_t b, const fp48_t c,
		const bn_t d) {
	int n0, n1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *_k, *_m;
	fp48_t r, t0[1 << (RLC_WIDTH - 2)];
	fp48_t s, t1[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	if (bn_is_zero(b)) {
		return fp48_exp_cyc(e, c, d);
	}

	if (bn_is_zero(d)) {
		return fp48_exp_cyc(e, a, b);
	}

	fp48_null(r);
	fp48_null(s);

	RLC_TRY {
		fp48_new(r);
		fp48_new(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp48_null(t0[i]);
			fp48_null(t1[i]);
			fp48_new(t0[i]);
			fp48_new(t1[i]);
		}

#if RLC_WIDTH > 2
		fp48_sqr(t0[0], a);
		fp48_mul(t0[1], t0[0], a);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp48_mul(t0[i], t0[i - 1], t0[0]);
		}

		fp48_sqr(t1[0], c);
		fp48_mul(t1[1], t1[0], c);
		for (int i = 2; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp48_mul(t1[i], t1[i - 1], t1[0]);
		}
#endif
		fp48_copy(t0[0], a);
		fp48_copy(t1[0], c);

		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, b, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, d, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		if (bn_sign(b) == RLC_NEG) {
			for (size_t i = 0; i < l0; i++) {
				naf0[i] = -naf0[i];
			}
		}
		if (bn_sign(d) == RLC_NEG) {
			for (size_t i = 0; i < l1; i++) {
				naf1[i] = -naf1[i];
			}
		}

		_k = naf0 + l - 1;
		_m = naf1 + l - 1;

		fp48_set_dig(r, 1);
		for (int i = l - 1; i >= 0; i--, _k--, _m--) {
			fp48_sqr(r, r);

			n0 = *_k;
			n1 = *_m;

			if (n0 > 0) {
				fp48_mul(r, r, t0[n0 / 2]);
			}
			if (n0 < 0) {
				fp48_inv_cyc(s, t0[-n0 / 2]);
				fp48_mul(r, r, s);
			}
			if (n1 > 0) {
				fp48_mul(r, r, t1[n1 / 2]);
			}
			if (n1 < 0) {
				fp48_inv_cyc(s, t1[-n1 / 2]);
				fp48_mul(r, r, s);
			}
		}

		fp48_copy(e, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp48_free(r);
		fp48_free(s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp48_free(t0[i]);
			fp48_free(t1[i]);
		}
	}
}

void fp48_exp_cyc_sps(fp48_t c, const fp48_t a, const int *b, size_t len,
		int sign) {
	size_t i, j, k, w = len;
    fp48_t t, *u = RLC_ALLOCA(fp48_t, w);

	if (len == 0) {
		RLC_FREE(u);
		fp48_set_dig(c, 1);
		return;
	}

	fp48_null(t);

	RLC_TRY {
		if (u == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < w; i++) {
			fp48_null(u[i]);
			fp48_new(u[i]);
		}
		fp48_new(t);

		fp48_copy(t, a);
		if (b[0] == 0) {
			for (j = 0, i = 1; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp48_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp48_inv_cyc(u[i - 1], t);
				} else {
					fp48_copy(u[i - 1], t);
				}
			}

			fp48_back_cyc_sim(u, u, w - 1);

			fp48_copy(c, a);
			for (i = 0; i < w - 1; i++) {
				fp48_mul(c, c, u[i]);
			}
		} else {
			for (j = 0, i = 0; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp48_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp48_inv_cyc(u[i], t);
				} else {
					fp48_copy(u[i], t);
				}
			}

			fp48_back_cyc_sim(u, u, w);

			fp48_copy(c, u[0]);
			for (i = 1; i < w; i++) {
				fp48_mul(c, c, u[i]);
			}
		}

		if (sign == RLC_NEG) {
			fp48_inv_cyc(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < w; i++) {
			fp48_free(u[i]);
		}
		fp48_free(t);
		RLC_FREE(u);
	}
}

void fp54_conv_cyc(fp54_t c, const fp54_t a) {
	fp54_t t;

	fp54_null(t);

	RLC_TRY {
		fp54_new(t);

		/* First, compute c = a^(p^27 - 1). */
		/* t = a^{-1}. */
		fp54_inv(t, a);
		/* c = a^(p^27). */
		fp54_inv_cyc(c, a);
		/* c = a^(p^27 - 1). */
		fp54_mul(c, c, t);

		/* Second, compute c^(p^9 + 1). */
		/* t = c^(p^9). */
		fp54_frb(t, c, 9);

		/* c = c^(p^9 + 1). */
		fp54_mul(c, c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp54_free(t);
	}
}

int fp54_test_cyc(const fp54_t a) {
	fp54_t t0, t1;
	int result = 0;

	fp54_null(t0);
	fp54_null(t1);

	RLC_TRY {
		fp54_new(t0);
		fp54_new(t1);

		/* Check if a^(p^18 - p^9 + 1) == 1. */
		fp54_frb(t0, a, 18);
		fp54_mul(t0, t0, a);
		fp54_frb(t1, a, 9);
		result = ((fp54_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp54_free(t0);
		fp54_free(t1);
	}

	return result;
}

void fp54_back_cyc(fp54_t c, const fp54_t a) {
	fp9_t t0, t1, t2;

	fp9_null(t0);
	fp9_null(t1);
	fp9_null(t2);

	RLC_TRY {
		fp9_new(t0);
		fp9_new(t1);
		fp9_new(t2);

		int f = fp9_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp9_copy(t2, a[2][0]);
		for (int j = 0; j < 3; j++) {
			dv_copy_cond(t2[j][0], a[2][1][j][0], RLC_FP_DIGS, f);
			dv_copy_cond(t2[j][1], a[2][1][j][1], RLC_FP_DIGS, f);
			dv_copy_cond(t2[j][2], a[2][1][j][2], RLC_FP_DIGS, f);
		}
		/* t0 = g4^2. */
		fp9_mul(t0, a[2][0], t2);
		fp9_dbl(t2, t0);
		for (int j = 0; j < 3; j++) {
			dv_copy_cond(t0[j][0], t2[j][0], RLC_FP_DIGS, f);
			dv_copy_cond(t0[j][1], t2[j][1], RLC_FP_DIGS, f);
			dv_copy_cond(t0[j][2], t2[j][2], RLC_FP_DIGS, f);
		}
		/* t1 = 3 * g4^2 - 2 * g3. */
		fp9_sub(t1, t0, a[1][1]);
		fp9_dbl(t1, t1);
		fp9_add(t1, t1, t0);
		/* t0 = E * g5^2 + t1. */
		fp9_sqr(t2, a[2][1]);
		fp9_mul_art(t0, t2);
		fp9_add(t0, t0, t1);
		/* t1 = (4 * g2). */
		fp9_dbl(t1, a[1][0]);
		fp9_dbl(t1, t1);
		for (int j = 0; j < 3; j++) {
			dv_copy_cond(t1[j][0], a[1][1][j][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[j][1], a[1][1][j][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[j][2], a[1][1][j][2], RLC_FP_DIGS, f);
		}
		/* If unity, decompress to unity as well. */
		f = fp54_cmp_dig(a, 1) == RLC_EQ;
		fp9_set_dig(t2, 1);
		for (int j = 0; j < 3; j++) {
			dv_copy_cond(t1[j][0], t2[j][0], RLC_FP_DIGS, f);
			dv_copy_cond(t1[j][1], t2[j][1], RLC_FP_DIGS, f);
			dv_copy_cond(t1[j][2], t2[j][2], RLC_FP_DIGS, f);
		}

		/* t1 = 1/(4 * g2). */
		fp9_dbl(t1, a[1][0]);
		fp9_dbl(t1, t1);
		fp9_inv(t1, t1);
		/* c_1 = g1. */
		fp9_mul(c[0][1], t0, t1);

		/* t1 = g3 * g4. */
		fp9_mul(t1, a[1][1], a[2][0]);
		/* t2 = 2 * g1^2 - 3 * g3 * g4. */
		fp9_sqr(t2, c[0][1]);
		fp9_sub(t2, t2, t1);
		fp9_dbl(t2, t2);
		fp9_sub(t2, t2, t1);
		/* t1 = g2 * g5. */
		fp9_mul(t1, a[1][0], a[2][1]);
		/* c_0 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
		fp9_add(t2, t2, t1);
		fp9_mul_art(c[0][0], t2);
		fp_add_dig(c[0][0][0][0], c[0][0][0][0], 1);

		fp9_copy(c[1][0], a[1][0]);
		fp9_copy(c[1][1], a[1][1]);
		fp9_copy(c[2][0], a[2][0]);
		fp9_copy(c[2][1], a[2][1]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp9_free(t0);
		fp9_free(t1);
		fp9_free(t2);
	}
}

void fp54_back_cyc_sim(fp54_t c[], const fp54_t a[], int n) {
    fp9_t *t = RLC_ALLOCA(fp9_t, n * 3);
    fp9_t *t0 = t + 0 * n, *t1 = t + 1 * n, *t2 = t + 2 * n;

	if (n == 0) {
		RLC_FREE(t);
		return;
	}

	RLC_TRY {
		if (t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (int i = 0; i < n; i++) {
			fp9_null(t0[i]);
			fp9_null(t1[i]);
			fp9_null(t2[i]);
			fp9_new(t0[i]);
			fp9_new(t1[i]);
			fp9_new(t2[i]);
		}

		for (int i = 0; i < n; i++) {
			int f = fp9_is_zero(a[i][1][0]);
			/* If f, t0[i] = 2 * g4 * g5, t1[i] = g3. */
			fp9_copy(t2[i], a[i][2][0]);
			for (int j = 0; j < 3; j++) {
				dv_copy_cond(t2[i][j][0], a[i][2][1][j][0], RLC_FP_DIGS, f);
				dv_copy_cond(t2[i][j][1], a[i][2][1][j][1], RLC_FP_DIGS, f);
				dv_copy_cond(t2[i][j][2], a[i][2][1][j][2], RLC_FP_DIGS, f);
			}
			/* t0[i] = g4^2. */
			fp9_mul(t0[i], a[i][2][0], t2[i]);
			fp9_dbl(t2[i], t0[i]);
			for (int j = 0; j < 3; j++) {
				dv_copy_cond(t0[i][j][0], t2[i][j][0], RLC_FP_DIGS, f);
				dv_copy_cond(t0[i][j][1], t2[i][j][1], RLC_FP_DIGS, f);
				dv_copy_cond(t0[i][j][2], t2[i][j][2], RLC_FP_DIGS, f);
			}
			/* t1[i] = 3 * g4^2 - 2 * g3. */
			fp9_sub(t1[i], t0[i], a[i][1][1]);
			fp9_dbl(t1[i], t1[i]);
			fp9_add(t1[i], t1[i], t0[i]);
			/* t0[i] = E * g5^2 + t1[i]. */
			fp9_sqr(t2[i], a[i][2][1]);
			fp9_mul_art(t0[i], t2[i]);
			fp9_add(t0[i], t0[i], t1[i]);
			/* t1[i] = (4 * g2). */
			fp9_dbl(t1[i], a[i][1][0]);
			fp9_dbl(t1[i], t1[i]);
			for (int j = 0; j < 3; j++) {
				dv_copy_cond(t1[i][j][0], a[i][1][1][j][0], RLC_FP_DIGS, f);
				dv_copy_cond(t1[i][j][1], a[i][1][1][j][1], RLC_FP_DIGS, f);
				dv_copy_cond(t1[i][j][2], a[i][1][1][j][2], RLC_FP_DIGS, f);
			}
			/* If unity, decompress to unity as well. */
			f = fp54_cmp_dig(a[i], 1) == RLC_EQ;
			fp9_set_dig(t2[i], 1);
			for (int j = 0; j < 3; j++) {
				dv_copy_cond(t1[i][j][0], t2[i][j][0], RLC_FP_DIGS, f);
				dv_copy_cond(t1[i][j][1], t2[i][j][1], RLC_FP_DIGS, f);
				dv_copy_cond(t1[i][j][2], t2[i][j][2], RLC_FP_DIGS, f);
			}
		}

		/* t1 = 1 / t1. */
		fp9_inv_sim(t1, t1, n);

		for (int i = 0; i < n; i++) {
			/* t0 = g1. */
			fp9_mul(c[i][0][1], t0[i], t1[i]);

			/* t1 = g3 * g4. */
			fp9_mul(t1[i], a[i][1][1], a[i][2][0]);
			/* t2 = 2 * g1^2 - 3 * g3 * g4. */
			fp9_sqr(t2[i], c[i][0][1]);
			fp9_sub(t2[i], t2[i], t1[i]);
			fp9_dbl(t2[i], t2[i]);
			fp9_sub(t2[i], t2[i], t1[i]);
			/* t1 = g2 * g5. */
			fp9_mul(t1[i], a[i][1][0], a[i][2][1]);
			/* t2 = E * (2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1. */
			fp9_add(t2[i], t2[i], t1[i]);
			fp9_mul_art(c[i][0][0], t2[i]);
			fp_add_dig(c[i][0][0][0][0], c[i][0][0][0][0], 1);

			fp9_copy(c[i][1][0], a[i][1][0]);
			fp9_copy(c[i][1][1], a[i][1][1]);
			fp9_copy(c[i][2][0], a[i][2][0]);
			fp9_copy(c[i][2][1], a[i][2][1]);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (int i = 0; i < n; i++) {
			fp9_free(t0[i]);
			fp9_free(t1[i]);
			fp9_free(t2[i]);
		}
		RLC_FREE(t);
	}
}

void fp54_exp_cyc(fp54_t c, const fp54_t a, const bn_t b) {
	int i, j, k, w = bn_ham(b);

	if (bn_is_zero(b)) {
		return fp54_set_dig(c, 1);
	}

	if ((bn_bits(b) > RLC_DIG) && ((w << 3) > bn_bits(b))) {
		fp54_t t;

		fp54_null(t)

		RLC_TRY {
			fp54_new(t);

			fp54_copy(t, a);

			for (i = bn_bits(b) - 2; i >= 0; i--) {
				fp54_sqr_cyc(t, t);
				if (bn_get_bit(b, i)) {
					fp54_mul(t, t, a);
				}
			}

			fp54_copy(c, t);
			if (bn_sign(b) == RLC_NEG) {
				fp54_inv_cyc(c, c);
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp54_free(t);
		}
	} else {
		fp54_t t, *u = RLC_ALLOCA(fp54_t, w);

		fp54_null(t);

		RLC_TRY {
			if (u == NULL) {
				RLC_THROW(ERR_NO_MEMORY)
			}
			for (i = 0; i < w; i++) {
				fp54_null(u[i]);
				fp54_new(u[i]);
			}
			fp54_new(t);

			j = 0;
			fp54_copy(t, a);
			for (i = 1; i < bn_bits(b); i++) {
				fp54_sqr_pck(t, t);
				if (bn_get_bit(b, i)) {
					fp54_copy(u[j++], t);
				}
			}

			if (!bn_is_even(b)) {
				j = 0;
				k = w - 1;
			} else {
				j = 1;
				k = w;
			}

			fp54_back_cyc_sim(u, u, k);

			if (!bn_is_even(b)) {
				fp54_copy(c, a);
			} else {
				fp54_copy(c, u[0]);
			}

			for (i = j; i < k; i++) {
				fp54_mul(c, c, u[i]);
			}

			if (bn_sign(b) == RLC_NEG) {
				fp54_inv_cyc(c, c);
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			for (i = 0; i < w; i++) {
				fp54_free(u[i]);
			}
			fp54_free(t);
			RLC_FREE(u);
		}
	}
}

void fp54_exp_cyc_sps(fp54_t c, const fp54_t a, const int *b, size_t len,
		int sign) {
	size_t i, j, k, w = len;
    fp54_t t, *u = RLC_ALLOCA(fp54_t, w);

	if (len == 0) {
		RLC_FREE(u);
		fp54_set_dig(c, 1);
		return;
	}

	fp54_null(t);

	RLC_TRY {
		if (u == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < w; i++) {
			fp54_null(u[i]);
			fp54_new(u[i]);
		}
		fp54_new(t);

		fp54_copy(t, a);
		if (b[0] == 0) {
			for (j = 0, i = 1; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp54_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp54_inv_cyc(u[i - 1], t);
				} else {
					fp54_copy(u[i - 1], t);
				}
			}

			fp54_back_cyc_sim(u, u, w - 1);

			fp54_copy(c, a);
			for (i = 0; i < w - 1; i++) {
				fp54_mul(c, c, u[i]);
			}
		} else {
			for (j = 0, i = 0; i < len; i++) {
				k = (b[i] < 0 ? -b[i] : b[i]);
				for (; j < k; j++) {
					fp54_sqr_pck(t, t);
				}
				if (b[i] < 0) {
					fp54_inv_cyc(u[i], t);
				} else {
					fp54_copy(u[i], t);
				}
			}

			fp54_back_cyc_sim(u, u, w);

			fp54_copy(c, u[0]);
			for (i = 1; i < w; i++) {
				fp54_mul(c, c, u[i]);
			}
		}

		if (sign == RLC_NEG) {
			fp54_inv_cyc(c, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < w; i++) {
			fp54_free(u[i]);
		}
		fp54_free(t);
		RLC_FREE(u);
	}
}
