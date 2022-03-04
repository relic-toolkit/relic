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
#define RLC_TABLE_SIZE			64

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if BN_MXP == BASIC || !defined(STRIP)

void bn_mxp_basic(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
	int i, l;
	bn_t t, u, r;

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (bn_is_zero(b)) {
		bn_set_dig(c, 1);
		return;
	}

	bn_null(t);
	bn_null(u);
	bn_null(r);

	RLC_TRY {
		bn_new(t);
		bn_new(u);
		bn_new(r);

		bn_mod_pre(u, m);

		l = bn_bits(b);

#if BN_MOD == MONTY
		bn_mod_monty_conv(t, a, m);
#else
		bn_copy(t, a);
#endif

		bn_copy(r, t);

		for (i = l - 2; i >= 0; i--) {
			bn_sqr(r, r);
			bn_mod(r, r, m, u);
			if (bn_get_bit(b, i)) {
				bn_mul(r, r, t);
				bn_mod(r, r, m, u);
			}
		}

#if BN_MOD == MONTY
		bn_mod_monty_back(r, r, m);
#endif

		if (bn_sign(b) == RLC_NEG) {
			bn_mod_inv(c, r, m);
		} else {
			bn_copy(c, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(u);
		bn_free(r);
	}
}

#endif

#if BN_MXP == SLIDE || !defined(STRIP)

void bn_mxp_slide(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
	bn_t tab[RLC_TABLE_SIZE], t, u, r;
	int i, j, l, w = 1;
	uint8_t *win = RLC_ALLOCA(uint8_t, bn_bits(b));

	if (win == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		RLC_FREE(win);
		bn_zero(c);
		return;
	}

	if (bn_is_zero(b)) {
		RLC_FREE(win);
		bn_set_dig(c, 1);
		return;
	}

	bn_null(t);
	bn_null(u);
	bn_null(r);
	/* Initialize table. */
	for (i = 0; i < RLC_TABLE_SIZE; i++) {
		bn_null(tab[i]);
	}

	/* Find window size. */
	i = bn_bits(b);
	if (i <= 21) {
		w = 2;
	} else if (i <= 32) {
		w = 3;
	} else if (i <= 128) {
		w = 4;
	} else if (i <= 256) {
		w = 5;
	} else if (i <= 512) {
		w = 6;
	} else {
		w = 7;
	}

	RLC_TRY {
		for (i = 0; i < (1 << (w - 1)); i++) {
			bn_new(tab[i]);
		}

		bn_new(t);
		bn_new(u);
		bn_new(r);
		bn_mod_pre(u, m);

#if BN_MOD == MONTY
		bn_set_dig(r, 1);
		bn_mod_monty_conv(r, r, m);
		bn_mod_monty_conv(t, a, m);
#else /* BN_MOD == BARRT || BN_MOD == RADIX */
		bn_set_dig(r, 1);
		bn_copy(t, a);
#endif

		bn_copy(tab[0], t);
		bn_sqr(t, tab[0]);
		bn_mod(t, t, m, u);
		/* Create table. */
		for (i = 1; i < 1 << (w - 1); i++) {
			bn_mul(tab[i], tab[i - 1], t);
			bn_mod(tab[i], tab[i], m, u);
		}

		l = bn_bits(b);
		bn_rec_slw(win, &l, b, w);
		for (i = 0; i < l; i++) {
			if (win[i] == 0) {
				bn_sqr(r, r);
				bn_mod(r, r, m, u);
			} else {
				for (j = 0; j < util_bits_dig(win[i]); j++) {
					bn_sqr(r, r);
					bn_mod(r, r, m, u);
				}
				bn_mul(r, r, tab[win[i] >> 1]);
				bn_mod(r, r, m, u);
			}
		}
		bn_trim(r);
#if BN_MOD == MONTY
		bn_mod_monty_back(r, r, m);
#endif

		if (bn_sign(b) == RLC_NEG) {
			bn_mod_inv(c, r, m);
		} else {
			bn_copy(c, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < (1 << (w - 1)); i++) {
			bn_free(tab[i]);
		}
		bn_free(u);
		bn_free(t);
		bn_free(r);
		RLC_FREE(win);
	}
}

#endif

#if BN_MXP == MONTY || !defined(STRIP)

void bn_mxp_monty(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
	bn_t tab[2], u;
	dig_t mask;
	int i, j, t;

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (bn_is_zero(b)) {
		bn_set_dig(c, 1);
		return;
	}

	bn_null(tab[0]);
	bn_null(tab[1]);
	bn_null(u);

	RLC_TRY {
		bn_new(u);
		bn_mod_pre(u, m);

		bn_new(tab[0]);
		bn_new(tab[1]);

#if BN_MOD == MONTY
		bn_set_dig(tab[0], 1);
		bn_mod_monty_conv(tab[0], tab[0], m);
		bn_mod_monty_conv(tab[1], a, m);
#else
		bn_set_dig(tab[0], 1);
		bn_mod(tab[1], a, m);
#endif

		bn_grow(tab[0], m->alloc);
		bn_grow(tab[1], m->alloc);
		for (i = bn_bits(b) - 1; i >= 0; i--) {
			j = bn_get_bit(b, i);
			dv_swap_cond(tab[0]->dp, tab[1]->dp, m->alloc, j ^ 1);
			mask = -(j ^ 1);
			t = (tab[0]->used ^ tab[1]->used) & mask;
			tab[0]->used ^= t;
			tab[1]->used ^= t;
			t = (tab[0]->sign ^ tab[1]->sign) & mask;
			tab[0]->sign ^= t;
			tab[1]->sign ^= t;
			bn_mul(tab[0], tab[0], tab[1]);
			bn_mod(tab[0], tab[0], m, u);
			bn_sqr(tab[1], tab[1]);
			bn_mod(tab[1], tab[1], m, u);
			dv_swap_cond(tab[0]->dp, tab[1]->dp, m->alloc, j ^ 1);
			mask = -(j ^ 1);
			t = (tab[0]->used ^ tab[1]->used) & mask;
			tab[0]->used ^= t;
			tab[1]->used ^= t;
			t = (tab[0]->sign ^ tab[1]->sign) & mask;
			tab[0]->sign ^= t;
			tab[1]->sign ^= t;
		}

#if BN_MOD == MONTY
		bn_mod_monty_back(u, tab[0], m);
#else
		bn_copy(u, tab[0]);
#endif

		if (bn_sign(b) == RLC_NEG) {
			bn_mod_inv(c, u, m);
		} else {
			bn_copy(c, u);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(tab[1]);
		bn_free(tab[0]);
		bn_free(u);
	}
}

#endif

void bn_mxp_dig(bn_t c, const bn_t a, dig_t b, const bn_t m) {
	int i, l;
	bn_t t, u, r;

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (b == 0) {
		bn_set_dig(c, 1);
		return;
	}

	bn_null(t);
	bn_null(u);
	bn_null(r);

	RLC_TRY {
		bn_new(t);
		bn_new(u);
		bn_new(r);

		bn_mod_pre(u, m);

		l = util_bits_dig(b);

#if BN_MOD == MONTY
		bn_mod_monty_conv(t, a, m);
#else
		bn_copy(t, a);
#endif

		bn_copy(r, t);

		for (i = l - 2; i >= 0; i--) {
			bn_sqr(r, r);
			bn_mod(r, r, m, u);
			if (b & ((dig_t)1 << i)) {
				bn_mul(r, r, t);
				bn_mod(r, r, m, u);
			}
		}

#if BN_MOD == MONTY
		bn_mod_monty_back(c, r, m);
#else
		bn_copy(c, r);
#endif
		/* Exponent is unsigned, so no need to invert if negative. */
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(u);
		bn_free(r);
	}
}


/****************************************************************
 * bn_t simultaneous exponentiation generalized Shamir trick
 * utility subroutine overwritting u, with precomputed table t
 ****************************************************************/
void _bn_mxp_sim(bn_t S, const bn_t P[BN_XPWDT], bn_t u[BN_XPWDT],
                 const bn_t T[BN_XPWDT], const bn_t mod) {
        // WARNING: overwrites u
    int iszeroexp = 0x1;
    for(uint64_t j=0; j<BN_XPWDT; ++j) {
        iszeroexp &= bn_is_zero(u[j]);
    }

    if (iszeroexp) {
        bn_set_dig(S,1); // all exponents zero, just return 1
        return;
    }

        // Select odd exponents
    uint64_t parities = !bn_is_even(u[0]);
    for(uint64_t j=1; j<BN_XPWDT; ++j) parities |= (!bn_is_even(u[j]))<<j;

        // Halving exponents
    for(uint64_t j=0; j<BN_XPWDT; ++j) {
        bn_hlv(u[j],u[j]);			// WARNING: u overwriten
    }

        // POwer up to the halves
    _bn_mxp_sim(S, P, u, T, mod);

        // One Squaring
    bn_sqr(S,S); bn_mod(S,S,mod);

        // One multiplication by the odd exponents
    if (parities) {
        bn_mul(S, S, T[parities]);
        bn_mod(S,S,mod);
    }
}

/****************************************************************
 * bn_t simultaneous exponentiation generalized Shamir trick and fixed width
 ****************************************************************/
void bn_mxp_sim(bn_t S, const bn_t P[BN_XPWDT], const bn_t u[BN_XPWDT], const bn_t mod) {
    const unsigned int TABLE_DIM = 1<<BN_XPWDT;
    bn_t T[TABLE_DIM], hu[BN_XPWDT];

    RLC_TRY {

        bn_null(T[0]); bn_new(T[0]); bn_set_dig(T[0],1);

            // Precompute all 2^{BN_XPWDT} combinations of points P
        for(uint64_t i=0; i<BN_XPWDT; ++i) {
            const uint64_t star = 1<<i; const uint64_t stars = star<<1;
            bn_null(T[star]); bn_new(T[star]); bn_copy(T[star], P[i]);
            for(uint64_t j=star+1; j<stars; ++j) {
                bn_null(T[j]); bn_new(T[j]);
                bn_mul(T[j], T[star], T[j-star]); bn_mod(T[j],T[j],mod);
            }
        }

            // copy u, as hu will be overwritten by the subroutine
        for(uint64_t j=0; j<BN_XPWDT; ++j) {
            bn_null(hu[j]); bn_new(hu[j]); bn_copy(hu[j],u[j]);
        }

            // Call the exponentiation subroutine
        _bn_mxp_sim(S,P,hu,T,mod);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
        for(uint64_t i=0; i<TABLE_DIM; ++i) { bn_free(T[i]); }
        for(uint64_t j=0; j<BN_XPWDT; ++j) { bn_free(hu[j]); }
    }
}

/****************************************************************
 * bn_t simultaneous exponentiation generalized Shamir trick any width
 ****************************************************************/
void bn_mxp_sim_lot(bn_t S, const bn_t P[], const bn_t u[], const bn_t mod, int n) {
    bn_t wP[BN_XPWDT], wu[BN_XPWDT], tmp;
	RLC_TRY {
            // Will use blocks of size BN_XPWDT
        bn_null(tmp); bn_new(tmp);
        for(uint64_t j=0; j<BN_XPWDT; ++j) {
            bn_null(wP[j]); bn_new(wP[j]);
            bn_null(wu[j]); bn_new(wu[j]);
        }

            // Largest multiple of BN_XPWDT lower than n
        const int endblockingloop = ( (n/BN_XPWDT)*BN_XPWDT );
        bn_set_dig(S, 1);
            // Exponentiate by blocks of size BN_XPWDT
        int i = 0; for(; i<endblockingloop; ) {
            for(uint64_t j=0; j<BN_XPWDT; ++j, ++i) {
                bn_copy(wP[j], P[i]);
                bn_copy(wu[j], u[i]);
            }
            bn_mxp_sim(tmp, wP, wu, mod);
            bn_mul(S, S, tmp);
            bn_mod(S, S, mod);
        }

            // Remaining (n-endblockingloop) exponentiations
        for(; i<n; ++i) {
            bn_mxp(tmp, P[i], u[i], mod);
            bn_mul(S, S, tmp);
            bn_mod(S, S, mod);
        }

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
        for(uint64_t j=0; j<BN_XPWDT; ++j) {
            bn_free(wP[j]); bn_free(wu[j]);
        }
        bn_free(tmp);
    }
}
