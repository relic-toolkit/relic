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
 * Implementation of multiplication in a sextic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

static void fp6_mul_toom3(fp6_t c, const fp6_t a, const fp6_t b) {
	fp2_t v0, v1, v2, t0, t1, t2, c3, c4;

	fp2_null(v0);
	fp2_null(v1);
	fp2_null(v2);
	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);
	fp2_null(c3);
	fp2_null(c4);

	RLC_TRY {
		fp2_new(v0);
		fp2_new(v1);
		fp2_new(v2);
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(c3);
		fp2_new(c4);

		fp2_add(v2, a[0], a[2]);
		fp2_add(v0, v2, a[1]);
		fp2_sub(v1, v2, a[1]);
		fp2_sub(v2, a[0], a[2]);
		fp_sub(v2[0], v2[0], a[1][1]);
		fp_add(v2[1], v2[1], a[1][0]);

		fp2_add(t2, b[0], b[2]);
		fp2_add(t0, t2, b[1]);
		fp2_sub(t1, t2, b[1]);
		fp2_sub(t2, b[0], b[2]);
		fp_sub(t2[0], t2[0], b[1][1]);
		fp_add(t2[1], t2[1], b[1][0]);

		fp2_mul(c4, a[2], b[2]);
		fp2_mul(c[0], a[0], b[0]);
		fp2_mul(c[1], v0, t0);
		fp2_mul(c[2], v1, t1);
		fp2_mul(c3, v2, t2);
		fp_hlv(c[1][0], c[1][0]);
		fp_hlv(c[1][1], c[1][1]);
		fp_hlv(c[2][0], c[2][0]);
		fp_hlv(c[2][1], c[2][1]);
		fp_hlv(c3[0], c3[0]);
		fp_hlv(c3[1], c3[1]);

		fp2_add(v0, c[0], c4);
		fp_hlv(t0[0], c[1][0]);
		fp_hlv(t0[1], c[1][1]);
		fp_sub(v1[0], t0[0], t0[1]);
		fp_add(v1[1], t0[0], t0[1]);
		fp_hlv(t0[0], c[2][0]);
		fp_hlv(t0[1], c[2][1]);
		fp_sub(t1[0], t0[0], t0[1]);
		fp_add(t1[1], t0[0], t0[1]);

		fp2_add(c[2], c[2], c[1]);
		fp2_sub(c[2], c[2], v0);
		fp_sub(t0[0], v0[1], c3[1]);
		fp_sub(t0[1], v0[0], c3[0]);
		fp_sub(c[1][0], v1[1], t0[0]);
		fp_sub(c[1][1], t0[1], v1[0]);
		fp_sub(c[1][0], c[1][0], t1[0]);
		fp_sub(c[1][1], c[1][1], t1[1]);
		fp_add(c3[0], v1[0], t0[0]);
		fp_sub(c3[1], v1[1], t0[1]);
		fp_sub(c3[0], c3[0], t1[1]);
		fp_add(c3[1], c3[1], t1[0]);

		fp_add(c[0][1], c[0][1], c3[0]);
		fp_add(c[0][1], c[0][1], c3[1]);
		fp_add(c[0][0], c[0][0], c3[0]);
		fp_sub(c[0][0], c[0][0], c3[1]);
		fp_add(c[1][1], c[1][1], c4[0]);
		fp_add(c[1][1], c[1][1], c4[1]);
		fp_add(c[1][0], c[1][0], c4[0]);
		fp_sub(c[1][0], c[1][0], c4[1]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t2);
		fp2_free(t1);
		fp2_free(t0);
		fp2_free(v2);
		fp2_free(v1);
		fp2_free(v0);
		fp2_free(c3);
		fp2_free(c4);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

void fp6_mul_basic(fp6_t c, const fp6_t a, const fp6_t b) {
#ifdef FP_QNRES
	fp6_mul_toom3(c, a, b);
#else
	fp2_t v0, v1, v2, t0, t1, t2;

	fp2_null(v0);
	fp2_null(v1);
	fp2_null(v2);
	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);

	RLC_TRY {
		fp2_new(v0);
		fp2_new(v1);
		fp2_new(v2);
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);

		/* v0 = a_0b_0 */
		fp2_mul(v0, a[0], b[0]);

		/* v1 = a_1b_1 */
		fp2_mul(v1, a[1], b[1]);

		/* v2 = a_2b_2 */
		fp2_mul(v2, a[2], b[2]);

		/* t2 (c_0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp2_add(t0, a[1], a[2]);
		fp2_add(t1, b[1], b[2]);
		fp2_mul(t2, t0, t1);
		fp2_sub(t2, t2, v1);
		fp2_sub(t2, t2, v2);
		fp2_mul_nor(t0, t2);
		fp2_add(t2, t0, v0);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
		fp2_add(t0, a[0], a[1]);
		fp2_add(t1, b[0], b[1]);
		fp2_mul(c[1], t0, t1);
		fp2_sub(c[1], c[1], v0);
		fp2_sub(c[1], c[1], v1);
		fp2_mul_nor(t0, v2);
		fp2_add(c[1], c[1], t0);

		/* c_2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
		fp2_add(t0, a[0], a[2]);
		fp2_add(t1, b[0], b[2]);
		fp2_mul(c[2], t0, t1);
		fp2_sub(c[2], c[2], v0);
		fp2_add(c[2], c[2], v1);
		fp2_sub(c[2], c[2], v2);

		/* c_0 = t2 */
		fp2_copy(c[0], t2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t2);
		fp2_free(t1);
		fp2_free(t0);
		fp2_free(v2);
		fp2_free(v1);
		fp2_free(v0);
	}
#endif
}

void fp6_mul_basic3(fp6_t c, const fp6_t a, const fp6_t b) {
	fp2_t v0, v1, v2, t0, t1, t2, c3, c4;

	fp2_null(v0);
	fp2_null(v1);
	fp2_null(v2);
	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);
	fp2_null(c3);
	fp2_null(c4);

	RLC_TRY {
		fp2_new(v0);
		fp2_new(v1);
		fp2_new(v2);
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(c3);
		fp2_new(c4);
#ifdef FP_QNRES
		fp2_add(v2, a[0], a[2]);
		fp2_add(v0, v2, a[1]);
		fp2_sub(v1, v2, a[1]);
		fp2_sub(v2, a[0], a[2]);
		fp_sub(v2[0], v2[0], a[1][1]);
		fp_add(v2[1], v2[1], a[1][0]);

		fp2_add(t2, b[0], b[2]);
		fp2_add(t0, t2, b[1]);
		fp2_sub(t1, t2, b[1]);
		fp2_sub(t2, b[0], b[2]);
		fp_sub(t2[0], t2[0], b[1][1]);
		fp_add(t2[1], t2[1], b[1][0]);

		fp2_mul(c4, a[2], b[2]);
		fp2_mul(c[0], a[0], b[0]);
		fp2_mul(c[1], v0, t0);
		fp2_mul(c[2], v1, t1);
		fp2_mul(c3, v2, t2);
		fp_hlv(c[1][0], c[1][0]);
		fp_hlv(c[1][1], c[1][1]);
		fp_hlv(c[2][0], c[2][0]);
		fp_hlv(c[2][1], c[2][1]);
		fp_hlv(c3[0], c3[0]);
		fp_hlv(c3[1], c3[1]);

		fp2_add(v0, c[0], c4);
		fp_hlv(t0[0], c[1][0]);
		fp_hlv(t0[1], c[1][1]);
		fp_sub(v1[0], t0[0], t0[1]);
		fp_add(v1[1], t0[0], t0[1]);
		fp_hlv(t0[0], c[2][0]);
		fp_hlv(t0[1], c[2][1]);
		fp_sub(t1[0], t0[0], t0[1]);
		fp_add(t1[1], t0[0], t0[1]);

		fp2_add(c[2], c[2], c[1]);
		fp2_sub(c[2], c[2], v0);
		fp_sub(t0[0], v0[1], c3[1]);
		fp_sub(t0[1], v0[0], c3[0]);
		fp_sub(c[1][0], v1[1], t0[0]);
		fp_sub(c[1][1], t0[1], v1[0]);
		fp_sub(c[1][0], c[1][0], t1[0]);
		fp_sub(c[1][1], c[1][1], t1[1]);
		fp_add(c3[0], v1[0], t0[0]);
		fp_sub(c3[1], v1[1], t0[1]);
		fp_sub(c3[0], c3[0], t1[1]);
		fp_add(c3[1], c3[1], t1[0]);

		fp_add(c[0][1], c[0][1], c3[0]);
		fp_add(c[0][1], c[0][1], c3[1]);
		fp_add(c[0][0], c[0][0], c3[0]);
		fp_sub(c[0][0], c[0][0], c3[1]);
		fp_add(c[1][1], c[1][1], c4[0]);
		fp_add(c[1][1], c[1][1], c4[1]);
		fp_add(c[1][0], c[1][0], c4[0]);
		fp_sub(c[1][0], c[1][0], c4[1]);
#else
		fp6_mul_basic(c, a, b);
#endif
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t2);
		fp2_free(t1);
		fp2_free(t0);
		fp2_free(v2);
		fp2_free(v1);
		fp2_free(v0);
		fp2_free(c3);
		fp2_free(c4);
	}
}

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

/* MSVC needs this to be exported, so remove inline */
void fp6_mul_unr(dv6_t c, const fp6_t a, const fp6_t b) {
	dv2_t u0, u1, u2, u3;
	fp2_t t0, t1;

	dv2_null(u0);
	dv2_null(u1);
	dv2_null(u2);
	dv2_null(u3);
	fp2_null(t0);
	fp2_null(t1);

	RLC_TRY {
		dv2_new(u0);
		dv2_new(u1);
		dv2_new(u2);
		dv2_new(u3);
		fp2_new(t0);
		fp2_new(t1);

		/* v0 = a_0b_0, v1 = a_1b_1, v2 = a_2b_2,
		 * t0 = a_1 + a_2, t1 = b_1 + b_2,
		 * u4 = u1 + u2, u5 = u0 + u1, u6 = u0 + u2 */
		fp2_muln_low(u0, a[0], b[0]);
		fp2_muln_low(u1, a[1], b[1]);
		fp2_muln_low(u2, a[2], b[2]);
#ifdef RLC_FP_ROOM
		fp2_addn_low(t0, a[1], a[2]);
		fp2_addn_low(t1, b[1], b[2]);
#else
		fp2_addm_low(t0, a[1], a[2]);
		fp2_addm_low(t1, b[1], b[2]);
#endif
		fp2_addc_low(c[0], u1, u2);

		/* t2 (c_0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp2_muln_low(u3, t0, t1);
		fp2_subc_low(u3, u3, c[0]);
		fp2_nord_low(c[0], u3);
		fp2_addc_low(c[0], c[0], u0);

		/* c_1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
#ifdef RLC_FP_ROOM
		fp2_addn_low(t0, a[0], a[1]);
		fp2_addn_low(t1, b[0], b[1]);
#else
		fp2_addm_low(t0, a[0], a[1]);
		fp2_addm_low(t1, b[0], b[1]);
#endif
		fp2_addc_low(c[1], u0, u1);
		fp2_muln_low(u3, t0, t1);
		fp2_subc_low(u3, u3, c[1]);
		fp2_nord_low(c[2], u2);
		fp2_addc_low(c[1], u3, c[2]);

		/* c_2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
#ifdef RLC_FP_ROOM
		fp2_addn_low(t0, a[0], a[2]);
		fp2_addn_low(t1, b[0], b[2]);
#else
		fp2_addm_low(t0, a[0], a[2]);
		fp2_addm_low(t1, b[0], b[2]);
#endif
		fp2_addc_low(c[2], u0, u2);
		fp2_muln_low(u3, t0, t1);
		fp2_subc_low(u3, u3, c[2]);
		fp2_addc_low(c[2], u3, u1);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv2_free(u0);
		dv2_free(u1);
		dv2_free(u2);
		dv2_free(u3);
		fp2_free(t0);
		fp2_free(t1);
	}
}

void fp6_mul_lazyr(fp6_t c, const fp6_t a, const fp6_t b) {
	dv6_t t;

	dv6_null(t);

	RLC_TRY {
		dv6_new(t);
		fp6_mul_unr(t, a, b);
		fp2_rdcn_low(c[0], t[0]);
		fp2_rdcn_low(c[1], t[1]);
		fp2_rdcn_low(c[2], t[2]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv6_free(t);
	}
}

#endif

void fp6_mul_dxs(fp6_t c, const fp6_t a, const fp6_t b) {
	fp2_t v0, v1, t0, t1, t2;

	fp2_null(v0);
	fp2_null(v1);
	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);

	RLC_TRY {
		fp2_new(v0);
		fp2_new(v1);
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);

		/* v0 = a_0b_0 */
		fp2_mul(v0, a[0], b[0]);

		/* v1 = a_1b_1 */
		fp2_mul(v1, a[1], b[1]);

		/* v2 = a_2b_2 = 0 */

		/* t2 (c0) = v0 + E((a_1 + a_2)(b_1 + b_2) - v1 - v2) */
		fp2_add(t0, a[1], a[2]);
		fp2_mul(t0, t0, b[1]);
		fp2_sub(t0, t0, v1);
		fp2_mul_nor(t2, t0);
		fp2_add(t2, t2, v0);

		/* c1 = (a_0 + a_1)(b_0 + b_1) - v0 - v1 + Ev2 */
		fp2_add(t0, a[0], a[1]);
		fp2_add(t1, b[0], b[1]);
		fp2_mul(c[1], t0, t1);
		fp2_sub(c[1], c[1], v0);
		fp2_sub(c[1], c[1], v1);

		/* c2 = (a_0 + a_2)(b_0 + b_2) - v0 + v1 - v2 */
		fp2_add(t0, a[0], a[2]);
		fp2_mul(c[2], t0, b[0]);
		fp2_sub(c[2], c[2], v0);
		fp2_add(c[2], c[2], v1);

		/* c0 = t2 */
		fp2_copy(c[0], t2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(v0);
		fp2_free(v1);
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
	}
}

void fp6_mul_art(fp6_t c, const fp6_t a) {
	fp2_t t0;

	fp2_null(t0);

	RLC_TRY {
		fp2_new(t0);

		/* (a_0 + a_1 * v + a_2 * v^2) * v = a_2 + a_0 * v + a_1 * v^2 */
		fp2_copy(t0, a[0]);
		fp2_mul_nor(c[0], a[2]);
		fp2_copy(c[2], a[1]);
		fp2_copy(c[1], t0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t0);
	}
}
