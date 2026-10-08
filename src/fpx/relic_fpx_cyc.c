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

TMPL_FPX_CONV_CYC_QUAD(fp2);

TMPL_FPX_TEST_CYC_QUAD(fp2);

TMPL_EXP_CYC_NAF(fp2, fp2_sqr);

TMPL_EXP_CYC_SIM(fp2, fp2_sqr);

TMPL_FPX_CONV_CYC_QUAD(fp8);

TMPL_FPX_TEST_CYC_QUAD(fp8);

TMPL_EXP_CYC_NAF(fp8, fp8_sqr_cyc);

TMPL_EXP_CYC_SIM(fp8, fp8_sqr_cyc);

TMPL_FPX_CONV_CYC(fp12, 2);

TMPL_FPX_TEST_CYC(fp12, 2);

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
		/* If all kept coefficients are zero, decompress to unity. */
		f = fp2_is_zero(a[0][1]) && fp2_is_zero(a[0][2]) &&
				fp2_is_zero(a[1][0]) && fp2_is_zero(a[1][2]);
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
			/* If all kept coefficients are zero, decompress to unity. */
			f = fp2_is_zero(a[i][0][1]) && fp2_is_zero(a[i][0][2]) &&
					fp2_is_zero(a[i][1][0]) && fp2_is_zero(a[i][1][2]);
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

TMPL_EXP_CYC_SIM(fp12, fp12_sqr_cyc);

TMPL_EXP_CYC_SPS(fp12);

TMPL_FPX_CONV_CYC_QUAD(fp16);

TMPL_FPX_TEST_CYC_QUAD(fp16);

TMPL_EXP_CYC_NAF(fp16, fp16_sqr_cyc);

TMPL_EXP_CYC_SIM(fp16, fp16_sqr_cyc);

TMPL_FPX_CONV_CYC(fp18, 3);

TMPL_FPX_TEST_CYC(fp18, 3);

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
		/* If all kept coefficients are zero, decompress to unity. */
		f = fp3_is_zero(a[0][1]) && fp3_is_zero(a[0][2]) &&
				fp3_is_zero(a[1][0]) && fp3_is_zero(a[1][2]);
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
			/* If all kept coefficients are zero, decompress to unity. */
			f = fp3_is_zero(a[i][0][1]) && fp3_is_zero(a[i][0][2]) &&
					fp3_is_zero(a[i][1][0]) && fp3_is_zero(a[i][1][2]);
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

TMPL_EXP_CYC_SIM(fp18, fp18_sqr_cyc);

TMPL_EXP_CYC_SPS(fp18);

TMPL_FPX_CONV_CYC(fp24, 4);

TMPL_FPX_TEST_CYC(fp24, 4);

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
		/* If all kept coefficients are zero, decompress to unity. */
		f = fp4_is_zero(a[1][0]) && fp4_is_zero(a[1][1]) &&
				fp4_is_zero(a[2][0]) && fp4_is_zero(a[2][1]);
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
			/* If all kept coefficients are zero, decompress to unity. */
			f = fp4_is_zero(a[i][1][0]) && fp4_is_zero(a[i][1][1]) &&
					fp4_is_zero(a[i][2][0]) && fp4_is_zero(a[i][2][1]);
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

TMPL_EXP_CYC_SIM(fp24, fp24_sqr_cyc);

TMPL_EXP_CYC_SPS(fp24);

TMPL_FPX_CONV_CYC(fp48, 8);

TMPL_FPX_TEST_CYC(fp48, 8);

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
		/* If all kept coefficients are zero, decompress to unity. */
		f = fp8_is_zero(a[0][1]) && fp8_is_zero(a[0][2]) &&
				fp8_is_zero(a[1][0]) && fp8_is_zero(a[1][2]);
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
			/* If all kept coefficients are zero, decompress to unity. */
			f = fp8_is_zero(a[i][0][1]) && fp8_is_zero(a[i][0][2]) &&
					fp8_is_zero(a[i][1][0]) && fp8_is_zero(a[i][1][2]);
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

TMPL_EXP_CYC_SIM(fp48, fp48_sqr_cyc);

TMPL_EXP_CYC_SPS(fp48);

TMPL_FPX_CONV_CYC(fp54, 9);

TMPL_FPX_TEST_CYC(fp54, 9);

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
		/* If all kept coefficients are zero, decompress to unity. */
		f = fp9_is_zero(a[1][0]) && fp9_is_zero(a[1][1]) &&
				fp9_is_zero(a[2][0]) && fp9_is_zero(a[2][1]);
		fp9_set_dig(t2, 1);
		fp9_copy_sec(t1, t2, f);

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
			/* If all kept coefficients are zero, decompress to unity. */
			f = fp9_is_zero(a[i][1][0]) && fp9_is_zero(a[i][1][1]) &&
					fp9_is_zero(a[i][2][0]) && fp9_is_zero(a[i][2][1]);
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
