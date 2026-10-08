/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of arithmetic in the quartic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"
#include "relic_fpx_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_FPX_UTIL(fp4, fp2, 2);

TMPL_FPX_BIN(fp4, fp2, 2, 4);

TMPL_FPX_CMP(fp4, fp2, 2);

TMPL_FPX_ADD(fp4, fp2, 2);

void fp4_add_dig(fp4_t c, const fp4_t a, dig_t dig) {
	fp2_add_dig(c[0], a[0], dig);
	fp2_copy(c[1], a[1]);
}

void fp4_sub_dig(fp4_t c, const fp4_t a, dig_t dig) {
	fp2_sub_dig(c[0], a[0], dig);
	fp2_copy(c[1], a[1]);
}

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_QUAD(fp4, fp2, fp2_mul_nor);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_QUAD(fp4, fp2, dv4, dv2, fp2, dv2, 1, 1,
		fp2_muln_low);

TMPL_FPX_MUL_LAZYR(fp4, dv4, fp2, dv2, 2);

#endif

TMPL_FPX_MUL_ART_QUAD(fp4, fp2, fp2_mul_nor);

void fp4_mul_frb(fp4_t c, const fp4_t a, int i, int j) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp_copy(t[0], core_get()->fp4_p1[0]);
		fp_copy(t[1], core_get()->fp4_p1[1]);

	    if (i == 1) {
			fp4_copy(c, a);
			for (int k = 0; k < j; k++) {
	        	fp2_mul(c[0], c[0], t);
				fp2_mul(c[1], c[1], t);
				if (ep_curve_is_pairf() == EP_FM16) {
					/* TODO: fix this ugly hack. */
					fp4_mul_art(c, c);
				}
				/* If constant in base field, then second component is zero. */
				if (core_get()->frb4 == 1) {
					fp4_mul_art(c, c);
					if (fp_prime_get_mod18() % 3 == 2) {
						fp4_mul_art(c, c);
					}
				}
			}
	    } else {
			RLC_THROW(ERR_NO_VALID);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t);
	}
}

void fp4_mul_dig(fp4_t c, const fp4_t a, dig_t b) {
	fp2_mul_dig(c[0], a[0], b);
	fp2_mul_dig(c[1], a[1], b);
}

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_SQR_QUAD(fp4, fp2, fp2_mul_nor);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

void fp4_sqr_unr(dv4_t c, const fp4_t a) {
	fp2_t t;
	dv2_t u0, u1;

	fp2_null(t);
	dv2_null_all(u0, u1);

	RLC_TRY {
		fp2_new(t);
		dv2_new_all(u0, u1);

		/* t0 = a^2. */
		fp2_sqrn_low(u0, a[0]);
		/* t1 = b^2. */
		fp2_sqrn_low(u1, a[1]);

		fp2_addm_low(t, a[0], a[1]);

		/* c = a^2  + b^2 * E. */
		fp2_nord_low(c[0], u1);
		fp2_addc_low(c[0], c[0], u0);

		/* d = (a + b)^2 - a^2 - b^2 = 2 * a * b. */
		fp2_addc_low(u1, u1, u0);
		fp2_sqrn_low(c[1], t);
		fp2_subc_low(c[1], c[1], u1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t);
		dv2_free_all(u0, u1);
	}
}

TMPL_FPX_SQR_LAZYR(fp4, dv4, fp2, dv2, 2);

#endif

TMPL_FPX_INV_CYC_QUAD(fp4, fp2);

TMPL_FPX_INV_QUAD(fp4, fp2, fp2_mul_nor);

TMPL_FPX_INV_SIM(fp4);

TMPL_FPX_EXP(fp4);

void fp4_frb(fp4_t c, const fp4_t a, int i) {
	/* Cost of a single multiplication in Fp^2 per Frobenius. */
	fp4_copy(c, a);
	for (; i % 4 > 0; i--) {
		fp2_frb(c[0], c[0], 1);
		fp2_frb(c[1], c[1], 1);
		if (fp_prime_get_mod18() % 3 == 1) {
			fp2_mul_frb(c[1], c[1], 1, 3);
		} else {
			fp2_mul_frb(c[1], c[1], 2, 1);
			fp2_mul_frb(c[1], c[1], 2, 1);
		}
	}
}

TMPL_FPX_IS_SQR(fp4, 4);

int fp4_srt(fp4_t c, const fp4_t a) {
	int c0, r = 0;
	fp2_t t0, t1, t2;

	fp2_null_all(t0, t1, t2);

	if (fp4_is_zero(a)) {
		fp4_zero(c);
		return 1;
	}

	RLC_TRY {
		fp2_new_all(t0, t1, t2);

		if (fp2_is_zero(a[1])) {
			/* special case: either a[0] is square and sqrt is purely 'real'
			 * or a[0] is non-square and sqrt is purely 'imaginary' */
			r = 1;
			if (fp2_is_sqr(a[0])) {
				fp2_srt(c[0], a[0]);
				fp2_zero(c[1]);
			} else {
				/* Compute a[0]/s^2. */
				fp2_set_dig(t0, 1);
				fp2_mul_nor(t0, t0);
				fp2_inv(t0, t0);
				fp2_mul(t0, a[0], t0);
				fp2_zero(c[0]);
				if (!fp2_srt(c[1], t0)) {
					/* should never happen! */
					RLC_THROW(ERR_NO_VALID);
				}
			}
		} else {
			/* t0 = a[0]^2 - s^2 * a[1]^2 */
			fp2_sqr(t0, a[0]);
			fp2_sqr(t1, a[1]);
			fp2_mul_nor(t2, t1);
			fp2_sub(t0, t0, t2);

			if (fp2_is_sqr(t0)) {
				fp2_srt(t1, t0);
				/* t0 = (a_0 + sqrt(t0)) / 2 */
				fp2_add(t0, a[0], t1);
				fp_hlv(t0[0], t0[0]);
				fp_hlv(t0[1], t0[1]);
				c0 = fp2_is_sqr(t0);
				/* t0 = (a_0 - sqrt(t0)) / 2 */
				fp2_sub(t1, a[0], t1);
				fp_hlv(t1[0], t1[0]);
				fp_hlv(t1[1], t1[1]);
				fp2_copy_sec(t0, t1, !c0);
				/* Should always be a quadratic residue. */
				fp2_srt(t2, t0);
				/* c_0 = sqrt(t0) */
				fp2_copy(c[0], t2);

				/* c_1 = a_1 / (2 * sqrt(t0)) */
				fp2_dbl(t2, t2);
				fp2_inv(t2, t2);
				fp2_mul(c[1], a[1], t2);
				r = 1;
			}
		}
	} RLC_CATCH_ANY {
		r = 0;
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free_all(t0, t1, t2);
	}
	return r;
}
