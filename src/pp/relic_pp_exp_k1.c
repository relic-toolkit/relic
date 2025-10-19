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
 * Implementation of the final exponentiation for curves of embedding degree 1.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_exp_k1(fp_t c, fp_t a) {
	bn_t e, n;
	size_t l;

	bn_null(n);
	bn_null(e);

	RLC_TRY {
		bn_new(n);
		bn_new(e);

		ep_curve_get_ord(n);

		bn_read_raw(e, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div(e, e, n);
		l = 0;
		while (bn_get_bit(e, l) == 0) {
			l++;
		}
		bn_rsh(e, e, l);
		fp_sqr(c, a);
		for (size_t i = 1; i < l; i++) {
			fp_sqr(c, c);
		}
		fp_exp(c, c, e);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(e);
	}
}
