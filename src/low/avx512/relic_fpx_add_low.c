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
 * Implementation of the low-level extension field additions in a Residue
 * Number System with AVX-512 IFMA, which add both components in one pass.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fp_rns_avx.h"

#define FP2_ADD_ASM

/* Fp3, and the products by the non-residue, are the portable versions. */
#include "../easy/relic_fpx_add_low.c"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Applies a residue-wise operation to both components of an element of Fp2.
 */
#define RNS_VMAP2(C, OP)													\
	const dig_t *_m = core_get()->rns.m;									\
	for (int _j = 0; _j < 2; _j++) {										\
		for (size_t _k = 0; _k < RNS_NE; _k++) {							\
			__m512i m = rns_load(_m, _k);									\
			rns_store(C[_j], _k, OP);										\
		}																	\
	}

/** Loads the current vector of a component inside RNS_VMAP2(). */
#define V2(A)		rns_load(A[_j], _k)

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_addn_low(fp2_t c, const fp2_t a, const fp2_t b) {
	RNS_VMAP2(c, rns_vadd(V2(a), V2(b), m));
}

void fp2_addm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	RNS_VMAP2(c, rns_vadd(V2(a), V2(b), m));
}

void fp2_addd_low(dv2_t c, dv2_t a, dv2_t b) {
	RNS_VMAP2(c, rns_vadd(V2(a), V2(b), m));
}

void fp2_addc_low(dv2_t c, dv2_t a, dv2_t b) {
	RNS_VMAP2(c, rns_vadd(V2(a), V2(b), m));
}

void fp2_subn_low(fp2_t c, const fp2_t a, const fp2_t b) {
	RNS_VMAP2(c, rns_vsub(V2(a), V2(b), m));
}

void fp2_subm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	RNS_VMAP2(c, rns_vsub(V2(a), V2(b), m));
}

void fp2_subd_low(dv2_t c, dv2_t a, dv2_t b) {
	RNS_VMAP2(c, rns_vsub(V2(a), V2(b), m));
}

void fp2_subc_low(dv2_t c, dv2_t a, dv2_t b) {
	RNS_VMAP2(c, rns_vsub(V2(a), V2(b), m));
}

void fp2_dbln_low(fp2_t c, const fp2_t a) {
	RNS_VMAP2(c, rns_vadd(V2(a), V2(a), m));
}

void fp2_dblm_low(fp2_t c, const fp2_t a) {
	RNS_VMAP2(c, rns_vadd(V2(a), V2(a), m));
}
