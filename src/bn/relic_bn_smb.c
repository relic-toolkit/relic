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
 * Implementation of Legendre and Jacobi symbols.
 *
 * @ingroup bn
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int bn_smb_leg(const bn_t a, const bn_t b) {
	bn_t t;
	int res;

	bn_null(t);

	if (bn_sign(b) == RLC_NEG) {
		RLC_THROW(ERR_NO_VALID);
		return 0;
	}

	if (bn_cmp(a, b) == RLC_EQ) {
		return 0;
	}

	RLC_TRY {
		bn_new(t);

		/* t = (b - 1)/2. */
		bn_sub_dig(t, b, 1);
		bn_rsh(t, t, 1);
		bn_mxp(t, a, t, b);
		res = 0;
		if (bn_cmp_dig(t, 1) == RLC_EQ) {
			res = 1;
		}
		bn_sub(t, b, t);
		if (bn_cmp_dig(t, 1) == RLC_EQ) {
			res = -1;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}

	return res;
}

int bn_smb_jac(const bn_t a, const bn_t b) {
	bn_t t0, t1, *_t0, *_t1, *_t;
	size_t z, a1, m1;
	int t;

	bn_null(t0);
	bn_null(t1);
	bn_null(r);

	/* Algorithm from "Optimized Computation of the Jacobi Symbol", by
	 * Lindstrøm and Chalkias: https://eprint.iacr.org/2024/1054.pdf */

	/* Argument b must be odd. */
	if (bn_is_even(b) || bn_sign(b) == RLC_NEG) {
		RLC_THROW(ERR_NO_VALID);
		return 0;
	}

	RLC_TRY {
		bn_new(t0);
		bn_new(t1);

		bn_mod(t0, a, b);
		bn_copy(t1, b);
		t = 1;
		m1 = bn_get_bit(t1, 1);

		_t0 = &t0;
		_t1 = &t1;

		while (!bn_is_zero(*_t0)) {
			z = 0;
			while (bn_is_even(*_t0)) {
				z++;
				bn_rsh(*_t0, *_t0, 1);
			}
			a1 = bn_get_bit(*_t0, 1);
			if (((z & 1) & (m1 ^ bn_get_bit(*_t1, 2))) ^ (a1 & m1)) {
				t = -t;
			}

			_t = _t0;
			_t0 = _t1;
			_t1 = _t;

			m1 = a1;

			bn_mod(*_t0, *_t0, *_t1);
		}

		if (bn_cmp_dig(*_t1, 1) != RLC_EQ) {
			t = 0;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t0);
		bn_free(t1);
	}

	return t;
}
