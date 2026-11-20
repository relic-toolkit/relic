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
 * Implementation of the residue symbols of composite order for prime fields.
 *
 * @ingroup fp
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smb6(const fp_t a) {
	int s = fp_smb2(a), k = fp_smb3(a);

	/* For p = 1 mod 3, a^((p - 1)/6) = z^m has a^((p - 1)/2) = (-1)^j =
	 * z^(3m) and a^((p - 1)/3) = w^k = z^(2m), so m = 3j + 4k mod 6, which for
	 * p = 2 mod 3, with k = 0, is the character of order 2 as z^3 = -1 to the
	 * power of j. Zero has k = -1. */
	return ((3 * ((1 - s) >> 1) + 4 * k + 6) % 6) | -(k < 0);
}

int fp_smb12(const fp_t a) {
	int j = fp_smb4(a), k = fp_smb3(a), c4 = 3, c3 = 8;

	/* For p = 1 mod 12, a^((p - 1)/12) = z^m has a^((p - 1)/4) = i^j = z^(3m)
	 * and a^((p - 1)/3) = w^k = z^(4m), so m = 9j + 4k mod 12. Otherwise the
	 * character of order g = gcd(12, p - 1) is z^(12/g) to the power of its
	 * exponent: 3j for g = 4, 2(3j/2 + 4k) for g = 6, with j even, and 3j for
	 * g = 2. The class of p is public. Zero has j = k = -1. */
	if (fp_prime_get_mod8() % 4 == 1 && fp_prime_get_mod18() % 3 == 1) {
		c4 = 9;
		c3 = 4;
	}
	return ((c4 * j + c3 * k + 24) % 12) | -(j < 0);
}
