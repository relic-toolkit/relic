/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of the final exponentiation for curves of embedding degree 16.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Computes the final exponentiation of a pairing defined over a KSS curve.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the extension field element to exponentiate.
 */
static void pp_exp_kss(fp16_t c, fp16_t a) {
	fp16_t t0, t1, t2, t3, t4, t5;
	const int *b;
	bn_t x;
	int l;

	bn_null(x);
	fp16_null(t0);
	fp16_null(t1);
	fp16_null(t2);
	fp16_null(t3);
	fp16_null(t4);
	fp16_null(t5);

	RLC_TRY {
		bn_new(x);
		fp16_new(t0);
		fp16_new(t1);
		fp16_new(t2);
		fp16_new(t3);
		fp16_new(t4);
		fp16_new(t5);

	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		fp16_free(t0);
		fp16_free(t1);
		fp16_free(t2);
		fp16_free(t3);
		fp16_free(t4);
		fp16_free(t5);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_exp_k16(fp16_t c, fp16_t a) {
	switch (ep_curve_is_pairf()) {
		case EP_K16:
			pp_exp_kss(c, a);
			break;
	}
}
