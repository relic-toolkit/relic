/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2024 RELIC Authors
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
 * Implementation of the prime functions to divide by small constants.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FP_ADD == BASIC || !defined(STRIP)

void fp_hlv_basic(fp_t c, const fp_t a) {
	dig_t carry = 0;

	if (a[0] & 1) {
		carry = fp_addn_low(c, a, fp_prime_get());
	} else {
		fp_copy(c, a);
	}
	fp_rsh1_low(c, c);
	if (carry) {
		c[RLC_FP_DIGS - 1] ^= ((dig_t)1 << (RLC_DIG - 1));
	}
}

#endif

#if FP_ADD == INTEG || !defined(STRIP)

void fp_hlv_integ(fp_t c, const fp_t a) {
	fp_hlvm_low(c, a);
}

#endif

void fp_trs(fp_t c, const fp_t a) {
	const dig_t mask = (2 * RLC_3MASK + 1);
	dig_t c0, c1, f0, f1;
	fp_t t;

	/* From "Efficient Multiplication in Finite Field Extensions of Degree 5"
	 * by El Mrabet, Guillevic and Ionica at ASIACRYPT 2011. */

	fp_null(t);

	RLC_TRY {
		fp_new(t);
		
		RLC_MUL_DIG(t[RLC_FP_DIGS - 1], f0, a[RLC_FP_DIGS - 1], mask);
		t[RLC_FP_DIGS - 1] >>= 1;
		c1 = a[RLC_FP_DIGS - 1] - 3 * t[RLC_FP_DIGS - 1];

		for (size_t i = RLC_FP_DIGS - 1; i > 0; i--) {
			c0 = c1;
			RLC_MUL_DIG(t[i - 1], f0, a[i - 1], mask);
			t[i - 1] >>= 1;
			c1 = c0 + a[i - 1] - 3 * t[i - 1];
			t[i - 1] += c0 * RLC_3MASK;
			f0 = ((c1 >> 1) & c1); /* c1 == 3 */
			f1 = ((c1 >> 2) & ~(c1 & 0x11)); /* c1 == 4 */
			f0 |= f1;
			t[i - 1] += f0;
			c1 = c1 - 3 * f0;
		}

		fp_copy(c, t);
		fp_sub(t, c, core_get()->over3.dp);
		fp_copy_sec(c, t, (c1 & 1) | (c1 >> 1)); // c1 >= 1
		fp_sub(t, c, core_get()->over3.dp);
		fp_copy_sec(c, t, c1 == 2);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(t);
	}
}