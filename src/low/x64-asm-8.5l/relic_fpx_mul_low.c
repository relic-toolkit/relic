/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of the low-level extension field multiplication functions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_muln_low(dv2_t c, const fp2_t a, const fp2_t b) {
	rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS], t2[2 * RLC_FP_DIGS];

	/* Karatsuba algorithm. RLC_FP_ROOM is not defined for this prime, since
	 * products of reduced elements already fill the 17 double-length limbs. */

	/* t0 = a_0 + a_1, t1 = b_0 + b_1. */
	fp_addm_low(t0, a[0], a[1]);
	fp_addm_low(t1, b[0], b[1]);
	/* c_0 = a_0 * b_0, c_1 = a_1 * b_1. */
	fp_muln_low(c[0], a[0], b[0]);
	fp_muln_low(c[1], a[1], b[1]);
	/* t2 = (a_0 + a_1) * (b_0 + b_1). */
	fp_muln_low(t2, t0, t1);

	/* t0 = (a_0 * b_0) + (a_1 * b_1). */
	fp_addc_low(t0, c[0], c[1]);

	/* c_0 = (a_0 * b_0) + u^2 * (a_1 * b_1). */
	if (fp_prime_get_qnr() == -5) {
		/* u^2 = -5: subtract a_1 * b_1 and 4 * a_1 * b_1. */
		fp_addc_low(t1, c[1], c[1]);
		fp_addc_low(t1, t1, t1);
		fp_subc_low(c[0], c[0], c[1]);
		fp_subc_low(c[0], c[0], t1);
	} else {
		fp_subc_low(c[0], c[0], c[1]);
		for (int i = -1; i > fp_prime_get_qnr(); i--) {
			fp_subc_low(c[0], c[0], c[1]);
		}
	}

	/* c_1 = t2 - t0. */
	fp_subc_low(c[1], t2, t0);
}

/* The assembly helpers take a = (a_0, a_1) and b = (b_0, b_1) packed as two
 * consecutive 9-limb vectors. */
void fp2_mulm_c0(dig_t *c, const dig_t *a, const dig_t *b);
void fp2_mulm_c1(dig_t *c, const dig_t *a, const dig_t *b);

void fp2_mulm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	rlc_align dig_t ta[2 * RLC_FP_DIGS], tb[2 * RLC_FP_DIGS];
	rlc_align dv2_t u;

	if (fp_prime_get_qnr() == -5) {
		/* The assembly helpers interleave the reduction with u^2 = -5. */
#if ALLOC == AUTO
		if (sizeof(fp_t) == RLC_FP_DIGS * sizeof(dig_t)) {
			fp2_mulm_c0(ta, a[0], b[0]);
			fp2_mulm_c1(c[1], a[0], b[0]);
			fp_copy(c[0], ta);
			return;
		}
#endif
		/* Pack the operands if their coordinates are not consecutive. */
		dv_copy(ta, a[0], RLC_FP_DIGS);
		dv_copy(ta + RLC_FP_DIGS, a[1], RLC_FP_DIGS);
		dv_copy(tb, b[0], RLC_FP_DIGS);
		dv_copy(tb + RLC_FP_DIGS, b[1], RLC_FP_DIGS);
		fp2_mulm_c0(c[0], ta, tb);
		fp2_mulm_c1(c[1], ta, tb);
		return;
	}

	dv2_null(u);

	RLC_TRY {
		dv2_new(u);
		fp2_muln_low(u, a, b);
		fp2_rdcn_low(c, u);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv2_free(u);
	}
}

void fp3_muln_low(dv3_t c, const fp3_t a, const fp3_t b) {
	rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS], t2[2 * RLC_FP_DIGS], t3[2 * RLC_FP_DIGS];
	rlc_align dig_t t4[2 * RLC_FP_DIGS], t5[2 * RLC_FP_DIGS], t6[2 * RLC_FP_DIGS];

	/* Karatsuba algorithm. */

	/* t0 = a_0 * b_0, t1 = a_1 * b_1, t2 = a_2 * b_2. */
	fp_muln_low(t0, a[0], b[0]);
	fp_muln_low(t1, a[1], b[1]);
	fp_muln_low(t2, a[2], b[2]);

	/* t3 = (a_1 + a_2) * (b_1 + b_2). */
#ifdef RLC_FP_ROOM
	fp_addn_low(t3, a[1], a[2]);
	fp_addn_low(t4, b[1], b[2]);
#else
	fp_addm_low(t3, a[1], a[2]);
	fp_addm_low(t4, b[1], b[2]);
#endif
	fp_muln_low(t5, t3, t4);
#ifdef RLC_FP_ROOM
	fp_addc_low(t6, t1, t2);
#else
	fp_addc_low(t6, t1, t2);
#endif
	fp_subc_low(t4, t5, t6);
	fp_addc_low(c[0], t0, t4);
	for (int i = 1; i < fp_prime_get_cnr(); i++) {
		fp_addc_low(c[0], c[0], t4);
	}
	for (int i = 0; i >= fp_prime_get_cnr(); i--) {
		fp_subc_low(c[0], c[0], t4);
	}

#ifdef RLC_FP_ROOM
	fp_addn_low(t4, a[0], a[1]);
	fp_addn_low(t5, b[0], b[1]);
#else
	fp_addm_low(t4, a[0], a[1]);
	fp_addm_low(t5, b[0], b[1]);
#endif
	fp_muln_low(t6, t4, t5);
#ifdef RLC_FP_ROOM
	fp_addc_low(t4, t0, t1);
#else
	fp_addc_low(t4, t0, t1);
#endif
	fp_subc_low(t4, t6, t4);
	fp_addc_low(c[1], t4, t2);
	for (int i = 1; i < fp_prime_get_cnr(); i++) {
		fp_addc_low(c[1], c[1], t2);
	}
	for (int i = 0; i >= fp_prime_get_cnr(); i--) {
		fp_subc_low(c[1], c[1], t2);
	}

#ifdef RLC_FP_ROOM
	fp_addn_low(t5, a[0], a[2]);
	fp_addn_low(t6, b[0], b[2]);
#else
	fp_addm_low(t5, a[0], a[2]);
	fp_addm_low(t6, b[0], b[2]);
#endif
	fp_muln_low(t4, t5, t6);
#ifdef RLC_FP_ROOM
	fp_addc_low(t6, t0, t2);
#else
	fp_addc_low(t6, t0, t2);
#endif
	fp_subc_low(t5, t4, t6);
	fp_addc_low(c[2], t5, t1);
}

void fp3_mulm_low(fp3_t c, const fp3_t a, const fp3_t b) {
	dv3_t t;

	dv3_null(t);

	RLC_TRY {
		dv3_new(t);
		fp3_muln_low(t, a, b);
		fp3_rdcn_low(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv3_free(t);
	}
}
