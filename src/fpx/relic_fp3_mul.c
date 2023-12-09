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
 * Implementation of multiplication in a cubic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_CBC == BASIC || !defined(STRIP)

void fp3_mul_basic(fp3_t c, const fp3_t a, const fp3_t b) {
	dv_t t, t0, t1, t2, t3, t4, t5, t6;

	dv_null(t);
	dv_null(t0);
	dv_null(t1);
	dv_null(t2);
	dv_null(t3);
	dv_null(t4);
	dv_null(t5);
	dv_null(t6);

	RLC_TRY {
		dv_new(t);
		dv_new(t0);
		dv_new(t1);
		dv_new(t2);
		dv_new(t3);
		dv_new(t4);
		dv_new(t5);
		dv_new(t6);

		/* Karatsuba algorithm. */

		/* t0 = a_0 * b_0, t1 = a_1 * b_1, t2 = a_2 * b_2. */
		fp_muln_low(t0, a[0], b[0]);
		fp_muln_low(t1, a[1], b[1]);
		fp_muln_low(t2, a[2], b[2]);

		/* t3 = (a_1 + a_2) * (b_1 + b_2). */
		fp_add(t3, a[1], a[2]);
		fp_add(t4, b[1], b[2]);
		fp_muln_low(t, t3, t4);
#ifdef RLC_FP_ROOM
		fp_addd_low(t6, t1, t2);
#else
		fp_addc_low(t6, t1, t2);
#endif
		fp_subc_low(t4, t, t6);
		fp_addc_low(t3, t0, t4);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_addc_low(t3, t3, t4);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_subc_low(t3, t3, t4);
		}

		fp_add(t4, a[0], a[1]);
		fp_add(t5, b[0], b[1]);
		fp_muln_low(t, t4, t5);
#ifdef RLC_FP_ROOM
		fp_addd_low(t4, t0, t1);
#else
		fp_addc_low(t4, t0, t1);
#endif
		fp_subc_low(t4, t, t4);
		fp_addc_low(t4, t4, t2);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_addc_low(t4, t4, t2);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_subc_low(t4, t4, t2);
		}

		fp_add(t5, a[0], a[2]);
		fp_add(t6, b[0], b[2]);
		fp_muln_low(t, t5, t6);
#ifdef RLC_FP_ROOM
		fp_addd_low(t6, t0, t2);
#else
		fp_addc_low(t6, t0, t2);
#endif
		fp_addc_low(t6, t0, t2);
		fp_subc_low(t5, t, t6);
		fp_addc_low(t5, t5, t1);

		/* c_0 = t3 mod p. */
		fp_rdc(c[0], t3);

		/* c_1 = t4 mod p. */
		fp_rdc(c[1], t4);

		/* c_2 = t5 mod p. */
		fp_rdc(c[2], t5);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		dv_free(t);
		dv_free(t0);
		dv_free(t1);
		dv_free(t2);
		dv_free(t3);
		dv_free(t4);
		dv_free(t5);
		dv_free(t6);
	}
}

#endif

#if FPX_CBC == INTEG || !defined(STRIP)

void fp3_mul_integ(fp3_t c, const fp3_t a, const fp3_t b) {
	fp3_mulm_low(c, a, b);
}

#endif

void fp3_mul_art(fp3_t c, const fp3_t a) {
	fp_t t;

	fp_null(t);

	RLC_TRY {
		fp_new(t);

		/* (a_0 + a_1 * u + a_2 * u^2) * u = a_0 * u + a_1 * u^2 + a_2 * u^3. */
		fp_copy(t, a[0]);
		fp_copy(c[0], a[2]);
		for (int i = 1; i < fp_prime_get_cnr(); i++) {
			fp_add(c[0], c[0], a[2]);
		}
		for (int i = 0; i >= fp_prime_get_cnr(); i--) {
			fp_sub(c[0], c[0], a[2]);
		}
		fp_copy(c[2], a[1]);
		fp_copy(c[1], t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t);
	}
}

void fp3_mul_nor(fp3_t c, const fp3_t a) {
	fp3_t t, u;

	fp3_null(t);
	fp3_null(u);

	RLC_TRY {
		fp3_new(t);
		fp3_new(u);

		fp3_mul_art(t, a);

		int cnr = fp3_field_get_cnr();
		cnr = (cnr < 0 ? -cnr : cnr);
		switch (fp_prime_get_mod18()) {
			case 1:
			case 7:
				if (cnr != 0) {
					fp3_copy(u, a);
					while (cnr > 1) {
						fp3_dbl(u, u);
						if (cnr & 1) {
							fp3_add(u, u, a);
						}
						cnr = cnr >> 1;
					}
					if (fp3_field_get_cnr() > 0) {
						fp3_add(t, t, u);
					} else {
						fp3_sub(t, t, u);
					}
				}
				break;
		}

		fp3_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(t);
		fp3_free(u);
	}
}

void fp3_mul_frb(fp3_t c, const fp3_t a, int i, int j) {
	ctx_t *ctx = core_get();

	fp3_copy(c, a);
	if (i % 3 == 0) {
		if (j % 3 == 1) {
			fp_mul(c[1], c[1], ctx->fp3_p0[0]);
			fp_mul(c[2], c[2], ctx->fp3_p0[1]);
		}
		if (j % 3 == 2) {
			fp_mul(c[1], c[1], ctx->fp3_p0[1]);
			fp_mul(c[2], c[2], ctx->fp3_p0[0]);
		}
	}

	if (fp3_field_get_cnr() == 0) {
		switch (i % 3) {
			case 1:
				fp_mul(c[0], c[0], ctx->fp3_p1[j - 1][0]);
				fp_mul(c[1], c[1], ctx->fp3_p1[j - 1][0]);
				fp_mul(c[2], c[2], ctx->fp3_p1[j - 1][0]);
				for (int k = 0; k < (j * ctx->frb3[0]) % 3; k++) {
					fp3_mul_nor(c, c);
				}
				break;
			case 2:
				fp_mul(c[0], c[0], ctx->fp3_p2[j - 1][0]);
				fp_mul(c[1], c[1], ctx->fp3_p2[j - 1][0]);
				fp_mul(c[2], c[2], ctx->fp3_p2[j - 1][0]);
				for (int k = 0; k < ctx->frb3[j]; k++) {
					fp3_mul_nor(c, c);
				}
				break;
		}
	} else {
#if ALLOC == AUTO
		switch (i) {
			case 1:
				fp3_mul(c, c, ctx->fp3_p1[j - 1]);
				break;
			case 2:
				fp3_mul(c, c, ctx->fp3_p2[j - 1]);
				break;
		}
#else
		fp3_t t;

		fp3_null(t);

		RLC_TRY {
			fp3_new(t);

			switch (i) {
				case 1:
					fp_copy(t[0], ctx->fp3_p1[j - 1][0]);
					fp_copy(t[1], ctx->fp3_p1[j - 1][1]);
					fp_copy(t[2], ctx->fp3_p1[j - 1][2]);
					fp3_mul(c, c, t);
					break;
				case 2:
					fp_copy(t[0], ctx->fp3_p2[j - 1][0]);
					fp_copy(t[1], ctx->fp3_p2[j - 1][1]);
					fp_copy(t[2], ctx->fp3_p2[j - 1][2]);
					fp3_mul(c, c, t);
					break;
			}
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			fp3_free(t);
		}
#endif
	}
}

void fp3_mul_dig(fp3_t c, const fp3_t a, dig_t b) {
	fp_mul_dig(c[0], a[0], b);
	fp_mul_dig(c[1], a[1], b);
	fp_mul_dig(c[2], a[2], b);
}
