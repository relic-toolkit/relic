/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Implementation of exponentiation in pairing groups.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void g1_mul(g1_t c, g1_t a, bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	TRY {
		bn_new(n);
		bn_new(_b);

		g1_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(G1_LOWER, mul)(c, a, _b);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul(g2_t c, g2_t a, bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	TRY {
		bn_new(n);
		bn_new(_b);

		g2_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(G2_LOWER, mul)(c, a, _b);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void gt_exp(gt_t c, gt_t a, bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	TRY {
		bn_new(n);
		bn_new(_b);

		gt_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(GT_LOWER, exp_cyc)(c, a, _b);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}
