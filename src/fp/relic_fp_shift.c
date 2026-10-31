/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the prime field arithmetic shift functions.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_lsh(fp_t c, const fp_t a, uint_t bits) {
#if FP_RDC == FP_RENUS
	/* Elements in RNS have no digits, so shift the value. */
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		fp_prime_back(t, a);
		bn_lsh(t, t, bits);
		bn_mod(t, t, &(core_get()->prime));
		fp_prime_conv(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
	}
#else
	int digits;

	RLC_RIP(bits, digits, bits);

	if (digits) {
		dv_lshd(c, a, RLC_FP_DIGS, digits);
	} else {
		if (c != a) {
			fp_copy(c, a);
		}
	}

	switch (bits) {
		case 0:
			break;
		case 1:
			fp_lsh1_low(c, c);
			break;
		default:
			fp_lshb_low(c, c, bits);
			break;
	}

#endif
}

void fp_rsh(fp_t c, const fp_t a, uint_t bits) {
#if FP_RDC == FP_RENUS
	/* Elements in RNS have no digits, so shift the value. */
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		fp_prime_back(t, a);
		bn_rsh(t, t, bits);
		fp_prime_conv(c, t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
	}
#else
	int digits;

	RLC_RIP(bits, digits, bits);

	if (digits) {
		dv_rshd(c, a, RLC_FP_DIGS, digits);
	} else {
		if (c != a) {
			fp_copy(c, a);
		}
	}

	switch (bits) {
		case 0:
			break;
		case 1:
			fp_rsh1_low(c, c);
			break;
		default:
			fp_rshb_low(c, c, bits);
			break;
	}
#endif
}
