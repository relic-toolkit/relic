/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2014 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of the prime elliptic curve utilities.
 *
 * @version $Id$
 * @ingroup ed
 */

#include "relic_core.h"

 #if FP_PRIME == 255
/**
 * Parameters for the Curve25519 prime elliptic curve.
 */
/** @{ */
#define CURVE_ED25519_A	"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"
#define CURVE_ED25519_D "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"
#define CURVE_ED25519_Y	"6666666666666666666666666666666666666666666666666666666666666658"
#define CURVE_ED25519_X "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a" 
#define CURVE_ED25519_R "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
#define CURVE_ED25519_H "0000000000000000000000000000000000000000000000000000000000000008"
/** @} */
#endif

void ed_recover_x(fp_t x, const fp_t y, const fp_t d) {
	fp_t tmpFP1;

	fp_null(tmpFP1);
	fp_new(tmpFP1);

	fp_mul(x, y, y);
	fp_sub_dig(x, x, 1);
	fp_mul(tmpFP1, d, y);
	fp_mul(tmpFP1, tmpFP1, y);
	fp_add_dig(tmpFP1, tmpFP1, 1);
	fp_inv(tmpFP1, tmpFP1);
	fp_mul(x, x, tmpFP1);
	fp_srt(x, x);
	fp_neg(x, x);

	fp_free(tmpFP1);
}


/**
 * Assigns a set of ordinary elliptic curve parameters.
 *
 * @param[in] CURVE		- the curve parameters to assign.
 * @param[in] FIELD		- the finite field identifier.
 */
#define ASSIGN_ED(CURVE, FIELD)												\
	fp_param_set(FIELD);													\
	FETCH(str, CURVE##_A, sizeof(CURVE##_A));								\
	fp_read_str(core_get()->ed_a, str, strlen(str), 16);					\
	FETCH(str, CURVE##_D, sizeof(CURVE##_D));								\
	fp_read_str(core_get()->ed_d, str, strlen(str), 16);					\
	FETCH(str, CURVE##_Y, sizeof(CURVE##_Y));								\
	fp_read_str(g->y, str, strlen(str), 16);								\
	FETCH(str, CURVE##_X, sizeof(CURVE##_X));								\
	fp_read_str(g->x, str, strlen(str), 16);								\
	fp_set_dig(g->z, 1);													\
	FETCH(str, CURVE##_R, sizeof(CURVE##_R));								\
	bn_read_str(r, str, strlen(str), 16);									\
	FETCH(str, CURVE##_H, sizeof(CURVE##_H));								\
	bn_read_str(h, str, strlen(str), 16);

void ed_param_set(int param) {
	core_get()->ed_id = 0;

	char str[2 * FP_BYTES + 2];

	ed_t g;
	bn_t r;
	bn_t h;

	ed_new(g);
	ed_null(g);

	bn_new(r);
	bn_null(r);

	bn_new(h);
	bn_null(h);

	switch(param) {
#if FP_PRIME == 255
		case CURVE_ED25519:
			ASSIGN_ED(CURVE_ED25519, PRIME_25519);
			break;
#else
	#error "No edwards curve supported with used FP_PRIME value."
#endif
	}

	bn_copy(&core_get()->ed_h, h);
	bn_copy(&core_get()->ed_r, r);
	ed_copy(&core_get()->ed_g, g);

	bn_free(r);
	bn_free(h);
	ed_free(g);
	core_get()->ed_id = param;
}

int ed_param_set_any(void) {
	ed_param_set(CURVE_ED25519);
	return 0;
}

int ed_param_get(void) {
	return core_get()->ed_id;
}

int ed_param_level() {
	switch (ed_param_get()) {
		case CURVE_ED25519:
			return 128;
	}
	return 0;
}


void ed_param_print(void) {
	switch (ed_param_get()) {
		case CURVE_ED25519:
			util_banner("Curve ED25519:", 0);
			break;
	}
}