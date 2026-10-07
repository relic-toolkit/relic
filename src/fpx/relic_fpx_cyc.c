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
#include "relic_fpx_cyc_tmpl.h"

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
		result = 0;
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

	fp2_null_all(r, s);

	RLC_TRY {
		fp2_new_all(r, s);
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
		fp2_free_all(r, s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp2_free(t[i]);
		}
	}
}

TMPL_EXP_CYC_SIM(fp2);

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
		result = 0;
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

	fp8_null_all(r, s);

	RLC_TRY {
		fp8_new_all(r, s);
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
		fp8_free_all(r, s);
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp8_free(t[i]);
		}
	}
}

TMPL_EXP_CYC_SIM(fp8);

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

	fp12_null_all(t0, t1);

	RLC_TRY {
		fp12_new_all(t0, t1);

		/* Check if a^(p^4 - p^2 + 1) == 1. */
		fp12_frb(t0, a, 4);
		fp12_mul(t0, t0, a);
		fp12_frb(t1, a, 2);

		result = ((fp12_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free_all(t0, t1);
	}

	return result;
}

void fp12_back_cyc(fp12_t c, const fp12_t a) {
	fp2_t t0, t1, t2;

	fp2_null_all(t0, t1, t2);

	RLC_TRY {
		fp2_new_all(t0, t1, t2);

		int f = fp2_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp2_copy(t2, a[0][1]);
		fp2_copy_sec(t2, a[1][2], f);
		/* t0 = g4^2. */
		fp2_mul(t0, a[0][1], t2);
		fp2_dbl(t2, t0);
		fp2_copy_sec(t0, t2, f);
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
		fp2_copy_sec(t1, a[0][2], f);
		/* If unity, decompress to unity as well. */
		f = fp12_cmp_dig(a, 1) == RLC_EQ;
		fp2_set_dig(t2, 1);
		fp2_copy_sec(t1, t2, f);

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
		fp2_free_all(t0, t1, t2);
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
			fp2_copy_sec(t2[i], a[i][1][2], f);
			/* t0 = g4^2. */
			fp2_mul(t0[i], a[i][0][1], t2[i]);
			fp2_dbl(t2[i], t0[i]);
			fp2_copy_sec(t0[i], t2[i], f);
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
			fp2_copy_sec(t1[i], a[i][0][2], f);
			/* If unity, decompress to unity as well. */
			f = (fp12_cmp_dig(a[i], 1) == RLC_EQ);
			fp2_set_dig(t2[i], 1);
			fp2_copy_sec(t1[i], t2[i], f);
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

TMPL_EXP_CYC(fp12);

TMPL_EXP_CYC_SIM(fp12);

TMPL_EXP_CYC_SPS(fp12);

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
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp16_free(t);
	}

	return result;
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

	fp16_null_all(r, s);

	RLC_TRY {
		fp16_new_all(r, s);
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 2)); i ++) {
			fp16_null(t[i]);
			fp16_new(t[i]);
		}

#if RLC_WIDTH > 2
		fp16_sqr_cyc(t[0], a);
		fp16_mul(t[1], t[0], a);
		for (int i = 2; i < (1 << (w - 2)); i++) {
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
		fp16_free_all(r, s);
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			fp16_free(t[i]);
		}
	}
}

TMPL_EXP_CYC_SIM(fp16);

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

	fp18_null_all(t0, t1);

	RLC_TRY {
		fp18_new_all(t0, t1);

		/* Check if a^(p^6 - p^3 + 1) == 1. */
		fp18_frb(t0, a, 6);
		fp18_mul(t0, t0, a);
		fp18_frb(t1, a, 3);

		result = ((fp18_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp18_free_all(t0, t1);
	}

	return result;
}

void fp18_back_cyc(fp18_t c, const fp18_t a) {
	fp3_t t0, t1, t2;

	fp3_null_all(t0, t1, t2);

	RLC_TRY {
		fp3_new_all(t0, t1, t2);

		int f = fp3_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp3_copy(t2, a[0][1]);
		fp3_copy_sec(t2, a[1][2], f);
		/* t0 = g4^2. */
		fp3_mul(t0, a[0][1], t2);
		fp3_dbl(t2, t0);
		fp3_copy_sec(t0, t2, f);
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
		fp3_copy_sec(t1, a[0][2], f);
		/* If unity, decompress to unity as well. */
		f = fp18_cmp_dig(a, 1) == RLC_EQ;
		fp3_set_dig(t2, 1);
		fp3_copy_sec(t1, t2, f);

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
		fp3_free_all(t0, t1, t2);
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
			fp3_copy_sec(t2[i], a[i][1][2], f);
			/* t0 = g4^2. */
			fp3_mul(t0[i], a[i][0][1], t2[i]);
			fp3_dbl(t2[i], t0[i]);
			fp3_copy_sec(t0[i], t2[i], f);
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
			fp3_copy_sec(t1[i], a[i][0][2], f);
			/* If unity, decompress to unity as well. */
			f = (fp18_cmp_dig(a[i], 1) == RLC_EQ);
			fp3_set_dig(t2[i], 1);
			fp3_copy_sec(t1[i], t2[i], f);
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

TMPL_EXP_CYC(fp18);

TMPL_EXP_CYC_SIM(fp18);

TMPL_EXP_CYC_SPS(fp18);

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

	fp24_null_all(t0, t1);

	RLC_TRY {
		fp24_new_all(t0, t1);

		/* Check if a^(p^8 - p^4 + 1) == 1. */
		fp24_frb(t0, a, 8);
		fp24_mul(t0, t0, a);
		fp24_frb(t1, a, 4);

		result = ((fp24_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp24_free_all(t0, t1);
	}

	return result;
}

void fp24_back_cyc(fp24_t c, const fp24_t a) {
	fp4_t t0, t1, t2;

	fp4_null_all(t0, t1, t2);

	RLC_TRY {
		fp4_new_all(t0, t1, t2);

		int f = fp4_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp4_copy(t2, a[2][0]);
		fp4_copy_sec(t2, a[2][1], f);
		/* t0 = g4^2. */
		fp4_mul(t0, a[2][0], t2);
		fp4_dbl(t2, t0);
		fp4_copy_sec(t0, t2, f);
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
		fp4_copy_sec(t1, a[1][1], f);
		/* If unity, decompress to unity as well. */
		f = fp24_cmp_dig(a, 1) == RLC_EQ;
		fp4_set_dig(t2, 1);
		fp4_copy_sec(t1, t2, f);

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
		fp4_free_all(t0, t1, t2);
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
			fp4_copy_sec(t2[i], a[i][2][1], f);
			/* t0 = g4^2. */
			fp4_mul(t0[i], a[i][2][0], t2[i]);
			fp4_dbl(t2[i], t0[i]);
			fp4_copy_sec(t0[i], t2[i], f);
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
			fp4_copy_sec(t1[i], a[i][1][1], f);
			/* If unity, decompress to unity as well. */
			f = fp24_cmp_dig(a[i], 1) == RLC_EQ;
			fp4_set_dig(t2[i], 1);
			fp4_copy_sec(t1[i], t2[i], f);
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

TMPL_EXP_CYC(fp24);

TMPL_EXP_CYC_SIM(fp24);

TMPL_EXP_CYC_SPS(fp24);

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

	fp48_null_all(t0, t1);

	RLC_TRY {
		fp48_new_all(t0, t1);

		/* Check if a^(p^16 - p^8 + 1) == 1. */
		fp48_frb(t0, a, 16);
		fp48_mul(t0, t0, a);
		fp48_frb(t1, a, 8);

		result = ((fp48_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp48_free_all(t0, t1);
	}

	return result;
}

void fp48_back_cyc(fp48_t c, const fp48_t a) {
	fp8_t t0, t1, t2;

	fp8_null_all(t0, t1, t2);

	RLC_TRY {
		fp8_new_all(t0, t1, t2);

		int f = fp8_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp8_copy(t2, a[0][1]);
		fp8_copy_sec(t2, a[1][2], f);
		/* t0 = g4^2. */
		fp8_mul(t0, a[0][1], t2);
		fp8_dbl(t2, t0);
		fp8_copy_sec(t0, t2, f);
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
		fp8_copy_sec(t1, a[0][2], f);
		/* If unity, decompress to unity as well. */
		f = fp48_cmp_dig(a, 1) == RLC_EQ;
		fp8_set_dig(t2, 1);
		fp8_copy_sec(t1, t2, f);

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
		fp8_free_all(t0, t1, t2);
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
			fp8_copy_sec(t2[i], a[i][1][2], f);
			/* t0[i] = g4^2. */
			fp8_mul(t0[i], a[i][0][1], t2[i]);
			fp8_dbl(t2[i], t0[i]);
			fp8_copy_sec(t0[i], t2[i], f);
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
			fp8_copy_sec(t1[i], a[i][0][2], f);
			/* If unity, decompress to unity as well. */
			f = fp48_cmp_dig(a[i], 1) == RLC_EQ;
			fp8_set_dig(t2[i], 1);
			fp8_copy_sec(t1[i], t2[i], f);
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

TMPL_EXP_CYC(fp48);

TMPL_EXP_CYC_SIM(fp48);

TMPL_EXP_CYC_SPS(fp48);

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

	fp54_null_all(t0, t1);

	RLC_TRY {
		fp54_new_all(t0, t1);

		/* Check if a^(p^18 - p^9 + 1) == 1. */
		fp54_frb(t0, a, 18);
		fp54_mul(t0, t0, a);
		fp54_frb(t1, a, 9);
		result = ((fp54_cmp(t0, t1) == RLC_EQ) ? 1 : 0);
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp54_free_all(t0, t1);
	}

	return result;
}

void fp54_back_cyc(fp54_t c, const fp54_t a) {
	fp9_t t0, t1, t2;

	fp9_null_all(t0, t1, t2);

	RLC_TRY {
		fp9_new_all(t0, t1, t2);

		int f = fp9_is_zero(a[1][0]);
		/* If f, t0 = 2 * g4 * g5, t1 = g3. */
		fp9_copy(t2, a[2][0]);
		fp9_copy_sec(t2, a[2][1], f);
		/* t0 = g4^2. */
		fp9_mul(t0, a[2][0], t2);
		fp9_dbl(t2, t0);
		fp9_copy_sec(t0, t2, f);
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
		fp9_copy_sec(t1, a[1][1], f);
		/* If unity, decompress to unity as well. */
		f = fp54_cmp_dig(a, 1) == RLC_EQ;
		fp9_set_dig(t2, 1);
		fp9_copy_sec(t1, t2, f);

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
		fp9_free_all(t0, t1, t2);
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
			fp9_copy_sec(t2[i], a[i][2][1], f);
			/* t0[i] = g4^2. */
			fp9_mul(t0[i], a[i][2][0], t2[i]);
			fp9_dbl(t2[i], t0[i]);
			fp9_copy_sec(t0[i], t2[i], f);
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
			fp9_copy_sec(t1[i], a[i][1][1], f);
			/* If unity, decompress to unity as well. */
			f = fp54_cmp_dig(a[i], 1) == RLC_EQ;
			fp9_set_dig(t2[i], 1);
			fp9_copy_sec(t1[i], t2[i], f);
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

TMPL_EXP_CYC(fp54);

TMPL_EXP_CYC_SPS(fp54);
