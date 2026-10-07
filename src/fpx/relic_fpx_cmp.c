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
 * Implementation of comparison in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"
#include "relic_fpx_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp2_cmp(const fp2_t a, const fp2_t b) {
	return (fp_cmp(a[0], b[0]) == RLC_EQ) && (fp_cmp(a[1], b[1]) == RLC_EQ) ?
			RLC_EQ : RLC_NE;
}

int fp2_cmp_dig(const fp2_t a, const dig_t b) {
	return (fp_cmp_dig(a[0], b) == RLC_EQ) && fp_is_zero(a[1]) ?
			RLC_EQ : RLC_NE;
}

int fp3_cmp(const fp3_t a, const fp3_t b) {
	return (fp_cmp(a[0], b[0]) == RLC_EQ) && (fp_cmp(a[1], b[1]) == RLC_EQ) &&
			(fp_cmp(a[2], b[2]) == RLC_EQ) ? RLC_EQ : RLC_NE;
}

int fp3_cmp_dig(const fp3_t a, const dig_t b) {
	return (fp_cmp_dig(a[0], b) == RLC_EQ) && fp_is_zero(a[1]) &&
			fp_is_zero(a[2]) ? RLC_EQ : RLC_NE;
}

TMPL_FPX_CMP(fp4, fp2, 2);

TMPL_FPX_CMP(fp6, fp2, 3);

TMPL_FPX_CMP(fp9, fp3, 3);

TMPL_FPX_CMP(fp8, fp4, 2);

TMPL_FPX_CMP(fp12, fp6, 2);

TMPL_FPX_CMP(fp16, fp8, 2);

TMPL_FPX_CMP(fp18, fp9, 2);

TMPL_FPX_CMP(fp24, fp8, 3);

TMPL_FPX_CMP(fp48, fp24, 2);

TMPL_FPX_CMP(fp54, fp18, 3);

