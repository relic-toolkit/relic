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

/* Fp2 is specific to this representation, while Fp3 is the portable version. */
#define FP2_ASM
#include "../easy/relic_fpx_mul_low.c"

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

/*
 * The assembly reads both coordinates from one contiguous vector, which only
 * automatic allocation without padding between coordinates guarantees.
 */
#if ALLOC != AUTO || ALIGN >= 16

void fp2_mulm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	rlc_align dv2_t u;

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

#endif
