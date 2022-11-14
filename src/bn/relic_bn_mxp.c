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
	size_t l, w = 1;
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
	for (size_t i = 0; i < RLC_TABLE_SIZE; i++) {
		bn_null(tab[i]);
	}

	/* Find window size. */
	l = bn_bits(b);
	if (l <= 21) {
		w = 2;
	} else if (l <= 32) {
		w = 3;
	} else if (l <= 128) {
		w = 4;
	} else if (l <= 256) {
		w = 5;
	} else if (l <= 512) {
		w = 6;
	} else {
		w = 7;
	}

	RLC_TRY {
		for (size_t i = 0; i < (1 << (w - 1)); i++) {
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
		for (size_t i = 1; i < 1 << (w - 1); i++) {
			bn_mul(tab[i], tab[i - 1], t);
			bn_mod(tab[i], tab[i], m, u);
		}

		bn_rec_slw(win, &l, b, w);
		for (size_t i = 0; i < l; i++) {
			if (win[i] == 0) {
				bn_sqr(r, r);
				bn_mod(r, r, m, u);
			} else {
				for (size_t j = 0; j < util_bits_dig(win[i]); j++) {
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
		for (size_t i = 0; i < (1 << (w - 1)); i++) {
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

void bn_mxp_crt(bn_t d, const bn_t a, const bn_t b, const bn_t c,
		const crt_t crt, int sqr) {
	bn_t t, u;

	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(t);
		bn_new(u);

		if (!sqr) {
#if MULTI == OPENMP
			omp_set_num_threads(CORES);
			#pragma omp parallel copyin(core_ctx) firstprivate(crt)
			{
				#pragma omp sections
				{
					#pragma omp section
					{
#endif
						/* m1 = a^dP mod p. */
						bn_mxp(t, a, b, crt->p);
#if MULTI == OPENMP
					}
#pragma omp section
					{
#endif
						/* m2 = a^dQ mod q. */
						bn_mxp(u, a, c, crt->q);
#if MULTI == OPENMP
					}
				}
			}
#endif
		} else {
#if MULTI == OPENMP
			omp_set_num_threads(CORES);
			#pragma omp parallel copyin(core_ctx) firstprivate(crt)
			{
				#pragma omp sections
				{
					#pragma omp section
					{
#endif
						/* Compute m_p = L(c^(p-1) mod p^2) * dp mod p. */
						bn_sqr(t, crt->p);
						bn_mxp(t, a, b, t);
						bn_sub_dig(t, t, 1);
						bn_div(t, t, crt->p);
						bn_mul(t, t, crt->dp);
						bn_mod(t, t, crt->p);
#if MULTI == OPENMP
					}
					#pragma omp section
					{
#endif
						/* Compute m_q = L(c^(q-1) mod q^2) * dq mod q. */
						bn_sqr(u, crt->q);
						bn_mxp(u, a, c, u);
						bn_sub_dig(u, u, 1);
						bn_div(u, u, crt->q);
						bn_mul(u, u, crt->dq);
						bn_mod(u, u, crt->q);
#if MULTI == OPENMP
					}
				}
			}
#endif
		}
		/* m1 = m1 - m2 mod p. */
		bn_sub(d, t, u);
		while (bn_sign(d) == RLC_NEG) {
			bn_add(d, d, crt->p);
		}
		/* m1 = qInv(m1 - m2) mod p. */
		bn_mul(d, d, crt->qi);
		bn_mod(d, d, crt->p);
		/* m = m2 + m1 * q. */
		bn_mul(d, d, crt->q);
		bn_add(d, d, u);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
		bn_free(u);
	}
}

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
    for(unsigned int j=0; j<BN_XPWDT; ++j) {
        iszeroexp &= bn_is_zero(u[j]);
    }

    if (iszeroexp) {
        bn_set_dig(S,1); // all exponents zero, just return 1
        return;
    }

        // Select odd exponents
    unsigned int parities = !bn_is_even(u[0]);
    for(unsigned int j=1; j<BN_XPWDT; ++j) parities |= (unsigned int)(!bn_is_even(u[j]))<<j;

        // Halving exponents
    for(unsigned int j=0; j<BN_XPWDT; ++j) {
        bn_hlv(u[j],u[j]);			// WARNING: u overwriten
    }

        // Recursive Power up to the halves
    _bn_mxp_sim(S, P, u, T, mod);

        // One Squaring
    bn_sqr(S,S); bn_mod(S,S,mod);

        // One multiplication by the odd exponents
    if (parities) {
        bn_mul(S, S, T[parities]);
        bn_mod(S,S,mod);
    }
}

#define BN_XPWDT_TABLE_SIZE (1u<<BN_XPWDT)

/****************************************************************
 * bn_t simultaneous exponentiation generalized Shamir trick and fixed width
 ****************************************************************/
void bn_mxp_sim(bn_t S, const bn_t P[BN_XPWDT], const bn_t u[BN_XPWDT], const bn_t mod) {
    bn_t hu[BN_XPWDT];
    bn_t T[BN_XPWDT_TABLE_SIZE];

    RLC_TRY {

        bn_null(T[0]); bn_new(T[0]); bn_set_dig(T[0],1);

            // Precompute all 2^{BN_XPWDT} combinations of points P
        for(unsigned int i=0; i<BN_XPWDT; ++i) {
            const unsigned int star = 1<<i; const unsigned int stars = star<<1;
            if (! bn_is_zero(u[i])) { // Otherwise will never need P[i]
                bn_null(T[star]); bn_new(T[star]); bn_copy(T[star], P[i]);
                for(unsigned int j=star+1; j<stars; ++j) {
                    bn_null(T[j]); bn_new(T[j]);
                    bn_mul(T[j], T[star], T[j-star]); bn_mod(T[j],T[j],mod);
                }
            }
        }

            // copy u, as hu will be overwritten by the subroutine
        for(unsigned int j=0; j<BN_XPWDT; ++j) {
            bn_null(hu[j]); bn_new(hu[j]); bn_copy(hu[j],u[j]);
        }

            // Call the exponentiation subroutine
        _bn_mxp_sim(S,P,hu,T,mod);

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
        bn_free(T[0]);
        for(unsigned int i=0; i<BN_XPWDT; ++i) {
            const unsigned int star = 1<<i; const unsigned int stars = star<<1;
            if (! bn_is_zero(u[i])) { // Otherwise P[i] was not needed
                bn_free(T[star]);
                for(unsigned int j=star+1; j<stars; ++j) {
                    bn_free(T[j]);
                }
            }
        }
        for(unsigned int j=0; j<BN_XPWDT; ++j) { bn_free(hu[j]); }
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
        for(unsigned int j=0; j<BN_XPWDT; ++j) {
            bn_null(wP[j]); bn_new(wP[j]);
            bn_null(wu[j]); bn_new(wu[j]);
        }

            // Largest multiple of BN_XPWDT lower than n
        const int endblockingloop = ( (n/BN_XPWDT)*BN_XPWDT );
        bn_set_dig(S, 1);
            // Exponentiate by blocks of size BN_XPWDT
        int i = 0; for(; i<endblockingloop; ) {
            for(unsigned int j=0; j<BN_XPWDT; ++j, ++i) {
                bn_copy(wP[j], P[i]);
                bn_copy(wu[j], u[i]);
            }
            bn_mxp_sim(tmp, wP, wu, mod);
            bn_mul(S, S, tmp);
            bn_mod(S, S, mod);
        }

            // Remaining (n-endblockingloop) exponentiations
        const int r=n-i;
        if (r) {
            if (r>1) {
                unsigned int j=0; for(; i<n; ++j, ++i) {
                    bn_copy(wP[j], P[i]);
                    bn_copy(wu[j], u[i]);
                }
                for(; j<BN_XPWDT; ++j) {	// Set remaining to exponent zero
                    bn_set_dig(wu[j], 0);
                }
                bn_mxp_sim(tmp, wP, wu, mod);
            } else { // A single exponent
                bn_mxp(tmp, P[i], u[i], mod);
            }
            bn_mul(S, S, tmp);
            bn_mod(S, S, mod);
        }

	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
        for(unsigned int j=0; j<BN_XPWDT; ++j) {
            bn_free(wP[j]); bn_free(wu[j]);
        }
        bn_free(tmp);
    }
}
