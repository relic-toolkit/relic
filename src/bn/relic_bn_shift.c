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
 * Implementation of the multiple precision arithmetic shift functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_dbl(bn_t c, const bn_t a) {
	dig_t carry;

	RLC_TRY {
		bn_grow(c, a->used + 1);

		c->used = a->used;
		carry = bn_lsh1_low(c->dp, a->dp, c->used);

		/* If there is an additional carry. */
		if (carry != 0) {
			c->dp[c->used] = carry;
			(c->used)++;
		}

		c->sign = a->sign;
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
}

void bn_hlv(bn_t c, const bn_t a) {
	bn_copy(c, a);
	bn_rsh1_low(c->dp, c->dp, c->used);
	bn_trim(c);
}

void bn_lsh(bn_t c, const bn_t a, uint_t bits) {
	int digits;
	dig_t carry;

	RLC_RIP(bits, digits, bits);

	RLC_TRY {
		bn_grow(c, a->used + digits + (bits > 0));

		c->used = a->used + digits;
		if (digits > 0) {
			dv_lshd(c->dp, a->dp, c->used, digits);
		} else {
			dv_copy(c->dp, a->dp, a->used);
		}
		c->sign = a->sign;

		if (bits > 0) {
			carry = bn_lshb_low(c->dp + digits, c->dp + digits,
				c->used - digits, bits);
			if (carry != 0) {
				c->dp[c->used] = carry;
				(c->used)++;
			}
		}
		bn_trim(c);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
}

void bn_rsh(bn_t c, const bn_t a, uint_t bits) {
	uint_t digits = 0;

	RLC_RIP(bits, digits, bits);

	RLC_TRY {
		bn_grow(c, a->used);

		if (digits > 0) {
			if (a->used > digits) {
				dv_rshd(c->dp, a->dp, a->used, digits);
				c->used = a->used - digits;
			} else {
				c->used = 0;
			}
		} else {
			dv_copy(c->dp, a->dp, a->used);
			c->used = a->used;
		}
		c->sign = a->sign;

		if (c->used > 0 && bits > 0) {
			bn_rshb_low(c->dp, c->dp, c->used, bits);
		}
		bn_trim(c);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
}
