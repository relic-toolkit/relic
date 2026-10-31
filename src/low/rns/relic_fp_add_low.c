/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of the low-level prime field addition and subtraction in a Residue Number
 * System.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t fp_add1_low(dig_t *c, const dig_t *a, dig_t digit) {
	RNS_MAP(c, rns_add(a[_i], rns_dig(digit, _i), _m[_i]));
	return 0;
}

dig_t fp_sub1_low(dig_t *c, const dig_t *a, dig_t digit) {
	RNS_MAP(c, rns_sub(a[_i], rns_dig(digit, _i), _m[_i]));
	return 0;
}

void fp_hlvm_low(dig_t *c, const dig_t *a) {
	fp_mulm_low(c, a, core_get()->rns.half);
}

void fp_hlvd_low(dig_t *c, const dig_t *a) {
	rlc_align dig_t t[RLC_FP_LEN];

	/* Reduce, then multiply by M/2 without reduction to stay unreduced. */
	fp_rns_rdc(t, a);
	fp_muln_low(c, t, core_get()->rns.half);
}

/* Defining FP_RNS_VEC leaves out the residue-wise functions, so that a backend
 * can replace them with vectorized ones. */
#ifndef FP_RNS_VEC

dig_t fp_addn_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_MAP(c, rns_add(a[_i], b[_i], _m[_i]));
	return 0;
}

void fp_addm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_MAP(c, rns_add(a[_i], b[_i], _m[_i]));
}

dig_t fp_addd_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_MAP(c, rns_add(a[_i], b[_i], _m[_i]));
	return 0;
}

void fp_addc_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_MAP(c, rns_add(a[_i], b[_i], _m[_i]));
}

dig_t fp_subn_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_MAP(c, rns_sub(a[_i], b[_i], _m[_i]));
	return 0;
}

void fp_subm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_MAP(c, rns_sub(a[_i], b[_i], _m[_i]));
}

dig_t fp_subd_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_MAP(c, rns_sub(a[_i], b[_i], _m[_i]));
	return 0;
}

void fp_subc_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_MAP(c, rns_sub(a[_i], b[_i], _m[_i]));
}

void fp_negm_low(dig_t *c, const dig_t *a) {
	RNS_MAP(c, rns_sub(0, a[_i], _m[_i]));
}

dig_t fp_dbln_low(dig_t *c, const dig_t *a) {
	RNS_MAP(c, rns_add(a[_i], a[_i], _m[_i]));
	return 0;
}

void fp_dblm_low(dig_t *c, const dig_t *a) {
	RNS_MAP(c, rns_add(a[_i], a[_i], _m[_i]));
}

#endif /* !FP_RNS_VEC */

#endif /* FP_RDC == FP_RENUS */
