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
 * Implementation of the low-level extension field additions in a Residue Number
 * System with AVX-512 IFMA, which add both components in one pass.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fp_rns_avx.h"

#define FP2_ADD_ASM
#define FP3_ADD_ASM

/* The products by the non-residues are the portable versions. */
#include "../easy/relic_fpx_add_low.c"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Applies a residue-wise operation to both components of an element of Fp2.
 */
#define RNS_VMAP2(C, OP)													\
	for (int _j = 0; _j < 2; _j++) {										\
		RNS_VMAP(C[_j], OP);												\
	}

/** Loads the current vector of a component inside RNS_VMAP2(). */
#define RNS_V2(A)	RNS_V(A[_j])

/**
 * Applies a residue-wise operation to the three components of an element of
 * Fp3, with RNS_V2() loading the current vector of a component.
 */
#define RNS_VMAP3(C, OP)													\
	for (int _j = 0; _j < 3; _j++) {										\
		RNS_VMAP(C[_j], OP);												\
	}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_addn_low(fp2_t c, const fp2_t a, const fp2_t b) {
	RNS_VMAP2(c, rns_vadd(RNS_V2(a), RNS_V2(b), _vm));
}

void fp2_addm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	RNS_VMAP2(c, rns_vadd(RNS_V2(a), RNS_V2(b), _vm));
}

void fp2_addd_low(dv2_t c, dv2_t a, dv2_t b) {
	RNS_VMAP2(c, rns_vadd(RNS_V2(a), RNS_V2(b), rns_vdv(_vm)));
}

void fp2_addc_low(dv2_t c, dv2_t a, dv2_t b) {
	RNS_VMAP2(c, rns_vadd(RNS_V2(a), RNS_V2(b), rns_vdv(_vm)));
}

void fp2_subn_low(fp2_t c, const fp2_t a, const fp2_t b) {
	RNS_VMAP2(c, rns_vsub(RNS_V2(a), RNS_V2(b), _vm));
}

void fp2_subm_low(fp2_t c, const fp2_t a, const fp2_t b) {
	RNS_VMAP2(c, rns_vsub(RNS_V2(a), RNS_V2(b), _vm));
}

void fp2_subd_low(dv2_t c, dv2_t a, dv2_t b) {
	RNS_VMAP2(c, rns_vsub(RNS_V2(a), RNS_V2(b), rns_vdv(_vm)));
}

void fp2_subc_low(dv2_t c, dv2_t a, dv2_t b) {
	RNS_VMAP2(c, rns_vsub(RNS_V2(a), RNS_V2(b), rns_vdv(_vm)));
}

void fp2_dbln_low(fp2_t c, const fp2_t a) {
	RNS_VMAP2(c, rns_vadd(RNS_V2(a), RNS_V2(a), _vm));
}

void fp2_dblm_low(fp2_t c, const fp2_t a) {
	RNS_VMAP2(c, rns_vadd(RNS_V2(a), RNS_V2(a), _vm));
}

void fp3_addn_low(fp3_t c, const fp3_t a, const fp3_t b) {
	RNS_VMAP3(c, rns_vadd(RNS_V2(a), RNS_V2(b), _vm));
}

void fp3_addm_low(fp3_t c, const fp3_t a, const fp3_t b) {
	RNS_VMAP3(c, rns_vadd(RNS_V2(a), RNS_V2(b), _vm));
}

void fp3_addd_low(dv3_t c, dv3_t a, dv3_t b) {
	RNS_VMAP3(c, rns_vadd(RNS_V2(a), RNS_V2(b), rns_vdv(_vm)));
}

void fp3_addc_low(dv3_t c, dv3_t a, dv3_t b) {
	RNS_VMAP3(c, rns_vadd(RNS_V2(a), RNS_V2(b), rns_vdv(_vm)));
}

void fp3_subn_low(fp3_t c, const fp3_t a, const fp3_t b) {
	RNS_VMAP3(c, rns_vsub(RNS_V2(a), RNS_V2(b), _vm));
}

void fp3_subm_low(fp3_t c, const fp3_t a, const fp3_t b) {
	RNS_VMAP3(c, rns_vsub(RNS_V2(a), RNS_V2(b), _vm));
}

void fp3_subd_low(dv3_t c, dv3_t a, dv3_t b) {
	RNS_VMAP3(c, rns_vsub(RNS_V2(a), RNS_V2(b), rns_vdv(_vm)));
}

void fp3_subc_low(dv3_t c, dv3_t a, dv3_t b) {
	RNS_VMAP3(c, rns_vsub(RNS_V2(a), RNS_V2(b), rns_vdv(_vm)));
}

void fp3_dbln_low(fp3_t c, const fp3_t a) {
	RNS_VMAP3(c, rns_vadd(RNS_V2(a), RNS_V2(a), _vm));
}

void fp3_dblm_low(fp3_t c, const fp3_t a) {
	RNS_VMAP3(c, rns_vadd(RNS_V2(a), RNS_V2(a), _vm));
}
