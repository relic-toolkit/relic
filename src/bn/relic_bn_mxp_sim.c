/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of the multiple precision exponentiation functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn_mxp_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Number of bases exponentiated together, each block using a precomputation
 * table of 2^RLC_BASES entries.
 */
#ifndef RLC_BASES
#define RLC_BASES	8
#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_mxp_sim(bn_t c, const bn_t a, const bn_t b, const bn_t d, const bn_t e,
		const bn_t m) {
	bn_t t0[2], t1[2];

	for (size_t i = 0; i < 2; i++) {
		bn_null(t0[i]);
		bn_null(t1[i]);
	}

	RLC_TRY {
		for (size_t i = 0; i < 2; i++) {
			bn_new(t0[i]);
			bn_new(t1[i]);
		}

		bn_copy(t0[0], a);
		bn_copy(t0[1], d);
		bn_copy(t1[0], b);
		bn_copy(t1[1], e);

		bn_mxp_sim_few(c, t0, t1, m, 2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (size_t i = 0; i < 2; i++) {
			bn_free(t0[i]);
			bn_free(t1[i]);
		}
	}
}

void bn_mxp_sim_few(bn_t c, const bn_t *a, const bn_t *b, const bn_t m,
		size_t n) {
	MXP_T *t = NULL, r;
	MXP_V u;
	bn_t z;
	size_t l;
	dig_t parities;

	if (bn_is_even(m)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (n == 0) {
		bn_set_dig(c, 1);
		return;
	}

	if (n > RLC_BASES) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	MXP_NULL(r);
	MXP_V_NULL(u);
	bn_null(z);
	t = RLC_ALLOCA(MXP_T, 1 << n);
	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	for (size_t i = 0; i < ((size_t)1 << n); i++) {
		MXP_NULL(t[i]);
	}

	RLC_TRY {
		MXP_V_NEW(u, m);
		for (size_t i = 0; i < ((size_t)1 << n); i++) {
			MXP_NEW(t[i], u);
		}
		MXP_NEW(r, u);
		bn_new(z);

		/* Precompute all 2^n combinations. */
		MXP_ONE(t[0], m, u);
		for (size_t i = 0; i < n; i++) {
			/* A zero exponent never selects the combinations with a[i]. */
			if (!bn_is_zero(b[i])) {
				const uint_t star = 1 << i;
				/* A negative exponent is a power of the inverse. */
				if (bn_sign(b[i]) == RLC_NEG) {
					bn_mod_inv(z, a[i], m);
					MXP_CONV(t[star], z, m, u);
				} else {
					MXP_CONV(t[star], a[i], m, u);
				}
				for (size_t j = star + 1; j < (star << 1); j++) {
					MXP_MUL(t[j], t[star], t[j - star], m, u);
				}
			}
		}

		l = bn_bits(b[0]);
		for (size_t j = 1; j < n; j++) {
			l = RLC_MAX(l, bn_bits(b[j]));
		}

		/* Accumulate in r, since c may alias m. */
		MXP_COPY(r, t[0], u);
		for (int i = l - 1; i >= 0; i--) {
			MXP_SQR(r, r, m, u);
			/* Multiply by the combination of bases with a bit set. */
			parities = bn_get_bit(b[0], i);
			for (size_t j = 1; j < n; j++) {
				parities |= (uint_t)(bn_get_bit(b[j], i)) << j;
			}
			if (parities) {
				MXP_MUL(r, r, t[parities], m, u);
			}
		}
		MXP_BACK(z, r, m, u);
		bn_copy(c, z);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (size_t i = 0; i < ((size_t)1 << n); i++) {
			MXP_FREE(t[i]);
		}
		RLC_FREE(t);
		MXP_FREE(r);
		MXP_V_FREE(u);
		bn_free(z);
	}
}

void bn_mxp_sim_lot(bn_t c, const bn_t *a, const bn_t *b, const bn_t m, size_t n) {
	uint_t i, j;
    bn_t _a[RLC_BASES], _b[RLC_BASES], r, t;

	if (bn_is_even(m)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	bn_null_all(r, t);
	for (j = 0; j < RLC_BASES; j++) {
		bn_null(_a[j]);
		bn_null(_b[j]);
	}

	RLC_TRY {
        // Will use blocks of size RLC_BASES
		bn_new_all(r, t);
        for(int j = 0; j < RLC_BASES; j++) {
			bn_new(_a[j]);
			bn_new(_b[j]);
        }

        // Largest multiple of RLC_BASES lower than n
        const size_t endblockingloop = ((n / RLC_BASES) * RLC_BASES);
        /* Accumulate in r, since c may alias m. */
        bn_set_dig(r, 1);
        // Exponentiate by blocks of size RLC_WIDTH
		for(i = 0; i < endblockingloop;) {
            for(j = 0; j < RLC_BASES; j++, i++) {
                bn_copy(_a[j], a[i]);
                bn_copy(_b[j], b[i]);
            }
            bn_mxp_sim_few(t, _a, _b, m, RLC_BASES);
            bn_mul(r, r, t);
            bn_mod(r, r, m);
        }

        // Remaining (n - endblockingloop) exponentiations
        if (n > i) {
			if (n == i + 1) {
				// A single exponent
                bn_mxp(t, a[i], b[i], m);
			} else {
				j = 0;
				for(; i < n; j++, i++) {
                    bn_copy(_a[j], a[i]);
                    bn_copy(_b[j], b[i]);
                }
                bn_mxp_sim_few(t, _a, _b, m, j);
            }
            bn_mul(r, r, t);
            bn_mod(r, r, m);
        }
        bn_copy(c, r);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
        for(j = 0; j < RLC_BASES; j++) {
            bn_free(_a[j]);
			bn_free(_b[j]);
        }
        bn_free_all(r, t);
    }
}
