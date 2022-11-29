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
 * Implementation of the multiple precision exponentiation functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Size of precomputation table.
 */
#define XP_WIDTH	RLC_MAX(8, RLC_WIDTH)

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
    bn_t *t = NULL, u;
	size_t l;
	dig_t parities;

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (n == 0) {
		return;
	}

	if (n > 8) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_null(u);
	t = RLC_ALLOCA(bn_t, 1 << n);
	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

    RLC_TRY {
		for (size_t i = 0; i < (1 << n); i++) {
			bn_null(t[i]);
			bn_new(t[i]);
		}
		bn_new(u);
		bn_mod_pre(u, m);

        // Precompute all 2^n combinations
		bn_set_dig(t[0], 1);
#if BN_MOD == MONTY
		bn_mod_monty_conv(t[0], t[0], m);
#endif
        for (size_t i = 0; i < n; i++) {
            if (!bn_is_zero(b[i])) { // Otherwise will never need P[i]
				const uint_t star = 1 << i;
#if BN_MOD == MONTY
				bn_mod_monty_conv(t[star], a[i], m);
#else
				bn_copy(t[star], a[i]);
#endif
                for(size_t j = star + 1; j < (star << 1); j++) {
                    bn_mul(t[j], t[star], t[j - star]);
					bn_mod(t[j], t[j], m, u);
                }
            }
        }

		l = bn_bits(b[0]);
	    for(size_t j = 1; j < n; j++) {
			l = RLC_MAX(l, bn_bits(b[j]));
	    }

		bn_copy(c, t[0]);
		for (int i = l - 1; i >= 0; i--) {
			// One Squaring
		    bn_sqr(c, c);
			bn_mod(c, c, m, u);
			// Select odd exponents
		    parities = bn_get_bit(b[0], i);
		    for(size_t j = 1; j < n; j++) {
				parities |= (uint_t)(bn_get_bit(b[j], i)) << j;
			}
			// One multiplication by the odd exponents
		    if (parities) {
		        bn_mul(c, c, t[parities]);
		        bn_mod(c, c, m, u);
		    }
		}
#if BN_MOD == MONTY
		bn_mod_monty_back(c, c, m);
#endif

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		for (size_t i = 0; i < (1 << n); i++) {
			bn_free(t[i]);
		}
		RLC_FREE(t);
		bn_free(u);
    }
}

void bn_mxp_sim_lot(bn_t c, const bn_t *a, const bn_t *b, const bn_t m, size_t n) {
	uint_t i, j;
    bn_t _a[XP_WIDTH], _b[XP_WIDTH], t;

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	RLC_TRY {
        // Will use blocks of size XP_WIDTH
        bn_null(t);
		bn_new(t);
        for(int j = 0; j < XP_WIDTH; j++) {
            bn_null(_a[j]);
            bn_null(_b[j]);
			bn_new(_a[j]);
			bn_new(_b[j]);
        }

        // Largest multiple of XP_WIDTH lower than n
        const int endblockingloop = ((n / XP_WIDTH) * XP_WIDTH);
        bn_set_dig(c, 1);
        // Exponentiate by blocks of size RLC_WIDTH
		for(i = 0; i < endblockingloop;) {
            for(j = 0; j < 8; j++, i++) {
                bn_copy(_a[j], a[i]);
                bn_copy(_b[j], b[i]);
            }
            bn_mxp_sim_few(t, _a, _b, m, XP_WIDTH);
            bn_mul(c, c, t);
            bn_mod(c, c, m);
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
            bn_mul(c, c, t);
            bn_mod(c, c, m);
        }
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
        for(j = 0; j < XP_WIDTH; j++) {
            bn_free(_a[j]);
			bn_free(_b[j]);
        }
        bn_free(t);
    }
}
