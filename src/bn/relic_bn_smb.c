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
	dis_t ai, bi, ci, di;
	dig_t n, d, t;
	bn_t t0, t1, t2, t3;
	uint_t z, i, s = (RLC_DIG >> 1) - 2;
	int r;

	bn_null(t0);
	bn_null(t1);
	bn_null(t2);
	bn_null(t3);

	/* Optimized Pornin's Algorithm by Aleksei Vambol from
	 * https://github.com/privacy-scaling-explorations/halo2curves/pull/95 */

	/* Argument b must be odd for Jacobi symbol. */
	if (bn_is_even(b) || bn_sign(b) == RLC_NEG) {
		RLC_THROW(ERR_NO_VALID);
		return 0;
	}

	RLC_TRY {
		bn_new(t0);
		bn_new(t1);
		bn_new(t2);
		bn_new(t3);

		bn_mod(t0, a, b);
		bn_copy(t1, b);
		t = 0;

		while (1) {
			ai = di = 1;
			bi = ci = 0;

			i = RLC_MAX(t0->used, t1->used);
			dv_zero(t0->dp + t0->used, i - t0->used);
			dv_zero(t1->dp + t1->used, i - t1->used);
			if (i == 1) {
				n = t0->dp[0];
				d = t1->dp[0];
				while (n != 0) {
					if (n & 1) {
						if (n < d) {
							RLC_SWAP(n, d);
							t ^= (n & d);
						}
						n = (n - d) >> 1;
						t ^= d ^ (d >> 1);
					} else {
						z = __builtin_ctz(n);
						t ^= (d ^ (d >> 1)) & (z << 1);
						n >>= z;
					}
				}
				r = (d == 1 ? 1 - (t & 2) : 0);
				break;
			}

			z = RLC_MIN(__builtin_clz(t0->dp[i - 1]), __builtin_clz(t1->dp[i - 1]));
			n = t0->dp[i - 1] << z;
			d = t1->dp[i - 1] << z;
			if (z > (RLC_DIG >> 1)) {
				n |= t0->dp[i - 2] >> z;
				d |= t1->dp[i - 2] >> z;
			}
			n = (n & RLC_HMASK) | (t0->dp[0] & RLC_LMASK);
			d = (d & RLC_HMASK) | (t1->dp[0] & RLC_LMASK);

			i = s;
			while (i > 0) {
				if (n & 1) {
					if (n < d) {
						RLC_SWAP(ai, ci);
						RLC_SWAP(bi, di);
						RLC_SWAP(n, d);
						t ^= (n & d);
					}
					n = (n - d) >> 1;
					ai = ai - ci;
					bi = bi - di;
					ci += ci;
					di += di;
					t ^= d ^ (d >> 1);
					i -= 1;
				} else {
					z = RLC_MIN(i, arch_tzcnt(n));
					t ^= (d ^ (d >> 1)) & (z << 1);
					ci = (dig_t)ci << z;
					di = (dig_t)di << z;
					n >>= z;
					i -= z;
				}
			}

			if (ai < 0) {
				bn_mul_dig(t2, t0, -ai);
				bn_neg(t2, t2);
			} else {
				bn_mul_dig(t2, t0, ai);
			}
			if (bi < 0) {
				bn_mul_dig(t3, t1, -bi);
				bn_neg(t3, t3);
			} else {
				bn_mul_dig(t3, t1, bi);
			}
			bn_add(t3, t3, t2);

			if (ci < 0) {
				bn_mul_dig(t2, t0, -ci);
				bn_neg(t2, t2);
			} else {
				bn_mul_dig(t2, t0, ci);
			}
			if (di < 0) {
				bn_mul_dig(t1, t1, -di);
				bn_neg(t1, t1);
			} else {
				bn_mul_dig(t1, t1, di);
			}
			bn_add(t1, t1, t2);
			bn_rsh(t1, t1, s);
			bn_rsh(t0, t3, s);

			if (bn_is_zero(t0)) {
				r = (bn_cmp_dig(t1, 1) == RLC_EQ ? 1 - (t & 2) : 0);
				break;
			}

			if (bn_sign(t0) == RLC_NEG) {
				t ^= t1->dp[0];
				bn_neg(t0, t0);
			}
			if (bn_sign(t1) == RLC_NEG) {
				bn_neg(t1, t1);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t0);
		bn_free(t1);
		bn_free(t2);
		bn_free(t3);
	}

	return r;
}
