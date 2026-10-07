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
 * Implementation of addition in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"
#include "relic_fpx_util_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_QDR == BASIC || !defined(STRIP)

void fp2_add_basic(fp2_t c, const fp2_t a, const fp2_t b) {
	fp_add(c[0], a[0], b[0]);
	fp_add(c[1], a[1], b[1]);
}

void fp2_sub_basic(fp2_t c, const fp2_t a, const fp2_t b) {
	fp_sub(c[0], a[0], b[0]);
	fp_sub(c[1], a[1], b[1]);
}

void fp2_dbl_basic(fp2_t c, const fp2_t a) {
	/* 2 * (a_0 + a_1 * u) = 2 * a_0 + 2 * a_1 * u. */
	fp_dbl(c[0], a[0]);
	fp_dbl(c[1], a[1]);
}

#endif

#if FPX_QDR == INTEG || !defined(STRIP)

void fp2_add_integ(fp2_t c, const fp2_t a, const fp2_t b) {
	fp2_addm_low(c, a, b);
}

void fp2_sub_integ(fp2_t c, const fp2_t a, const fp2_t b) {
	fp2_subm_low(c, a, b);
}

void fp2_dbl_integ(fp2_t c, const fp2_t a) {
	fp2_dblm_low(c, a);
}

#endif

void fp2_add_dig(fp2_t c, const fp2_t a, dig_t dig) {
	fp_add_dig(c[0], a[0], dig);
	fp_copy(c[1], a[1]);
}

void fp2_sub_dig(fp2_t c, const fp2_t a, dig_t dig) {
	fp_sub_dig(c[0], a[0], dig);
	fp_copy(c[1], a[1]);
}

void fp2_neg(fp2_t c, const fp2_t a) {
	fp_neg(c[0], a[0]);
	fp_neg(c[1], a[1]);
}

#if FPX_CBC == BASIC || !defined(STRIP)

void fp3_add_basic(fp3_t c, const fp3_t a, const fp3_t b) {
	fp_add(c[0], a[0], b[0]);
	fp_add(c[1], a[1], b[1]);
	fp_add(c[2], a[2], b[2]);
}

void fp3_sub_basic(fp3_t c, const fp3_t a, const fp3_t b) {
	fp_sub(c[0], a[0], b[0]);
	fp_sub(c[1], a[1], b[1]);
	fp_sub(c[2], a[2], b[2]);
}

void fp3_dbl_basic(fp3_t c, const fp3_t a) {
  /* 2 * (a_0 + a_1 * u) = 2 * a_0 + 2 * a_1 * u. */
	fp_dbl(c[0], a[0]);
	fp_dbl(c[1], a[1]);
	fp_dbl(c[2], a[2]);
}

#endif

void fp3_add_dig(fp3_t c, const fp3_t a, dig_t dig) {
	fp_add_dig(c[0], a[0], dig);
	fp_copy(c[1], a[1]);
	fp_copy(c[2], a[2]);
}

void fp3_sub_dig(fp3_t c, const fp3_t a, dig_t dig) {
	fp_sub_dig(c[0], a[0], dig);
	fp_copy(c[1], a[1]);
	fp_copy(c[2], a[2]);
}

void fp3_neg(fp3_t c, const fp3_t a) {
	fp_neg(c[0], a[0]);
	fp_neg(c[1], a[1]);
	fp_neg(c[2], a[2]);
}

#if FPX_CBC == INTEG || !defined(STRIP)

void fp3_add_integ(fp3_t c, const fp3_t a, const fp3_t b) {
	fp3_addm_low(c, a, b);
}

void fp3_sub_integ(fp3_t c, const fp3_t a, const fp3_t b) {
	fp3_subm_low(c, a, b);
}

void fp3_dbl_integ(fp3_t c, const fp3_t a) {
	fp3_dblm_low(c, a);
}

#endif

TMPL_FPX_ADD(fp4, fp2, 2);

void fp4_add_dig(fp4_t c, const fp4_t a, dig_t dig) {
	fp2_add_dig(c[0], a[0], dig);
	fp2_copy(c[1], a[1]);
}

void fp4_sub_dig(fp4_t c, const fp4_t a, dig_t dig) {
	fp2_sub_dig(c[0], a[0], dig);
	fp2_copy(c[1], a[1]);
}

TMPL_FPX_ADD(fp6, fp2, 3);

TMPL_FPX_ADD(fp8, fp4, 2);

TMPL_FPX_ADD(fp9, fp3, 3);

TMPL_FPX_ADD(fp12, fp6, 2);

TMPL_FPX_ADD(fp16, fp8, 2);

TMPL_FPX_ADD(fp18, fp9, 2);

TMPL_FPX_ADD(fp24, fp8, 3);

TMPL_FPX_ADD(fp48, fp24, 2);

TMPL_FPX_ADD(fp54, fp18, 3);

