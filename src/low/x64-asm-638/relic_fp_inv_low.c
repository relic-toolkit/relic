/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2012 RELIC Authors
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
 * Implementation of the low-level inversion functions.
 *
 * @&version $Id: relic_fp_inv_low.c 677 2011-03-05 22:19:43Z dfaranha $
 * @ingroup fp
 */

#include "relic_bn.h"
#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"
#include "relic_error.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_invn_low(dig_t *c, dig_t *a) {
	bn_t t;
	int i, k;

	fp_null(t);

	TRY {
		bn_new(t);

		k = fp_invn_asm(t->dp, a);
		t->used = FP_DIGS;

		/* If k < Wt then x1 = x1 * R^2 * R^{-1} mod p. */
		if (k <= FP_DIGS * FP_DIGIT) {
			fp_mul(t->dp, t->dp, fp_prime_get_conv());
			k = k + FP_DIGS * FP_DIGIT;
		}

		/* x1 = x1 * R^2 * R^{-1} mod p. */
		fp_mul(t->dp, t->dp, fp_prime_get_conv());

		/* c = x1 * 2^(2Wt - k) * R^{-1} mod p. */
		fp_copy(c, t->dp);
		dv_zero(t->dp, FP_DIGS);
		bn_set_2b(t, 2 * FP_DIGS * FP_DIGIT - k);
		fp_mul(c, c, t->dp);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp_free(t);
	}
}
