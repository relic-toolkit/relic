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
 * Implementation of the low-level prime field addition and subtraction in a
 * Residue Number System with AVX-512 IFMA.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

#if FP_RDC == FP_RENUS

#include "relic_fp_rns_avx.h"

#define FP_RNS_VEC

/* The functions that are not residue-wise are the portable versions. */
#include "../rns/relic_fp_add_low.c"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

dig_t fp_addn_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vadd(V(a), V(b), m));
	return 0;
}

void fp_addm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vadd(V(a), V(b), m));
}

dig_t fp_addd_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vadd(V(a), V(b), m));
	return 0;
}

void fp_addc_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vadd(V(a), V(b), m));
}

dig_t fp_subn_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vsub(V(a), V(b), m));
	return 0;
}

void fp_subm_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vsub(V(a), V(b), m));
}

dig_t fp_subd_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vsub(V(a), V(b), m));
	return 0;
}

void fp_subc_low(dig_t *c, const dig_t *a, const dig_t *b) {
	RNS_VMAP(c, rns_vsub(V(a), V(b), m));
}

void fp_negm_low(dig_t *c, const dig_t *a) {
	RNS_VMAP(c, rns_vsub(_mm512_setzero_si512(), V(a), m));
}

dig_t fp_dbln_low(dig_t *c, const dig_t *a) {
	RNS_VMAP(c, rns_vadd(V(a), V(a), m));
	return 0;
}

void fp_dblm_low(dig_t *c, const dig_t *a) {
	RNS_VMAP(c, rns_vadd(V(a), V(a), m));
}

#endif /* FP_RDC == FP_RENUS */
