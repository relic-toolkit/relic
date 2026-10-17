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
 * Implementation of the low-level extension field squaring functions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

/* Fp2 is specific to this representation, while Fp3 is the portable version. */
#define FP2_ASM
#include "../easy/relic_fpx_sqr_low.c"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_sqrn_low(dv2_t c, const fp2_t a) {
	rlc_align dig_t t0[2 * RLC_FP_DIGS], t1[2 * RLC_FP_DIGS], t2[2 * RLC_FP_DIGS];

	if (fp_prime_get_qnr() == -5) {
		/* c_0 = (a_0 + a_1) * (a_0 - 5 * a_1) + 4 * a_0 * a_1. */
		/* t0 = (a0 + a1). */
		fp_addm_low(t0, a[0], a[1]);
		/* t1 = a0 - 5 * a1. */
		fp_subm_low(t1, a[0], a[1]);
		fp_dblm_low(t2, a[1]);
		fp_dblm_low(t2, t2);
		fp_subm_low(t1, t1, t2);
		/* c1 = a0 * a1. */
		fp_muln_low(c[1], a[0], a[1]);
		/* c0 = (a0 + a1) * (a0 - 5 * a1). */
		fp_muln_low(c[0], t0, t1);
		/* c1 = 2 * a0 * a1, c0 = c0 + 2 * c1. */
		fp_addc_low(c[1], c[1], c[1]);
		fp_addc_low(t2, c[1], c[1]);
		fp_addc_low(c[0], c[0], t2);
	} else {
		/* c_0 = a_0^2 + u^2 * a_1^2, c_1 = 2 * a_0 * a_1. */
		fp_muln_low(c[0], a[0], a[0]);
		fp_muln_low(t0, a[1], a[1]);
		for (int i = 0; i > fp_prime_get_qnr(); i--) {
			fp_subc_low(c[0], c[0], t0);
		}
		for (int i = 0; i < fp_prime_get_qnr(); i++) {
			fp_addc_low(c[0], c[0], t0);
		}
		fp_dblm_low(t1, a[0]);
		fp_muln_low(c[1], t1, a[1]);
	}
	/* c = c0 + c1 * u. */
}

/*
 * The assembly reads both coordinates from one contiguous vector, which only
 * automatic allocation without padding between coordinates guarantees.
 */
#if RLC_ALLOC != RLC_AUTO || RLC_ALIGN >= 16

void fp2_sqrm_low(fp2_t c, const fp2_t a) {
	rlc_align dig_t t0[RLC_FP_DIGS], t1[RLC_FP_DIGS], t2[RLC_FP_DIGS];
	rlc_align dv2_t t;

	if (fp_prime_get_qnr() == -5) {
		/* fp_mulm_low() takes products below p * 2^576, so the unreduced sum
		 * t0 < 2p and the double t2 < 2p are valid inputs. */
		/* t0 = a0 + a1, t1 = a0 - 5 * a1. */
		fp_addn_low(t0, a[0], a[1]);
		fp_subm_low(t1, a[0], a[1]);
		fp_dblm_low(t2, a[1]);
		fp_dblm_low(t2, t2);
		fp_subm_low(t1, t1, t2);
		/* c1 = 2 * a0 * a1. */
		fp_dbln_low(t2, a[0]);
		fp_mulm_low(c[1], t2, a[1]);
		/* c0 = (a0 + a1) * (a0 - 5 * a1) + 2 * c1. */
		fp_mulm_low(c[0], t0, t1);
		fp_dblm_low(t2, c[1]);
		fp_addm_low(c[0], c[0], t2);
		return;
	}

	dv2_null(t);

	RLC_TRY {
		dv2_new(t);
		fp2_sqrn_low(t, a);
		fp2_rdcn_low(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		dv2_free(t);
	}
}

#endif
