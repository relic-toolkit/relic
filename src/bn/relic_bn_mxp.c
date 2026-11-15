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
#include "relic_bn_low.h"
#include "relic_bn_mxp_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Bit length below which the window is not worth the table it precomputes,
 * and the binary method is faster. Measured at moduli of 1024 and 2048 bits.
 */
#define BN_MXP_BITS	17

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_mxp_basic(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
	int i, l;
	MXP_T r, t;
	MXP_V u;
	bn_t z;

	if (bn_is_even(m)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (bn_is_zero(b)) {
		bn_set_dig(c, 1);
		return;
	}

	MXP_NULL(r);
	MXP_NULL(t);
	MXP_V_NULL(u);
	bn_null(z);

	RLC_TRY {
		MXP_V_NEW(u, m);
		MXP_NEW(r, u);
		MXP_NEW(t, u);
		bn_new(z);

		l = bn_bits(b);

		MXP_CONV(t, a, m, u);
		MXP_COPY(r, t, u);
		for (i = l - 2; i >= 0; i--) {
			MXP_SQR(r, r, m, u);
			if (bn_get_bit(b, i)) {
				MXP_MUL(r, r, t, m, u);
			}
		}
		MXP_BACK(z, r, m, u);

		/* Check the sign before writing c, which may alias b. */
		if (bn_sign(b) == RLC_NEG) {
			bn_mod_inv(c, z, m);
		} else {
			bn_copy(c, z);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		MXP_FREE(r);
		MXP_FREE(t);
		MXP_V_FREE(u);
		bn_free(z);
	}
}

void bn_mxp_slide(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
	MXP_T *tab, t;
	MXP_V u;
	bn_t z;
	size_t l, w = 1;
	uint8_t *win = RLC_ALLOCA(uint8_t, bn_bits(b));

	if (win == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	if (bn_is_even(m)) {
		RLC_FREE(win);
		RLC_THROW(ERR_NO_VALID);
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

	if (bn_bits(b) < BN_MXP_BITS) {
		/* The binary method is the faster of the two while the exponent is
		 * too short to pay for the table below. */
		RLC_FREE(win);
		bn_mxp_basic(c, a, b, m);
		return;
	}

	MXP_NULL(t);
	MXP_V_NULL(u);
	bn_null(z);

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

	tab = RLC_ALLOCA(MXP_T, (1 << (w - 1)));
	if (tab == NULL) {
		RLC_FREE(win);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}
	for (size_t i = 0; i < ((size_t)1 << (w - 1)); i++) {
		MXP_NULL(tab[i]);
	}

	RLC_TRY {
		MXP_V_NEW(u, m);
		for (size_t i = 0; i < ((size_t)1 << (w - 1)); i++) {
			MXP_NEW(tab[i], u);
		}
		MXP_NEW(t, u);
		bn_new(z);

		MXP_CONV(t, a, m, u);

		MXP_COPY(tab[0], t, u);
		MXP_SQR(t, tab[0], m, u);
		/* Create table. */
		for (size_t i = 1; i < ((size_t)1 << (w - 1)); i++) {
			MXP_MUL(tab[i], tab[i - 1], t, m, u);
		}

		MXP_ONE(t, m, u);

		bn_rec_slw(win, &l, b, w);
		for (size_t i = 0; i < l; i++) {
			if (win[i] == 0) {
				MXP_SQR(t, t, m, u);
			} else {
				for (size_t j = 0; j < util_bits_dig(win[i]); j++) {
					MXP_SQR(t, t, m, u);
				}
				MXP_MUL(t, t, tab[win[i] >> 1], m, u);
			}
		}

		MXP_BACK(z, t, m, u);

		if (bn_sign(b) == RLC_NEG) {
			bn_mod_inv(c, z, m);
		} else {
			bn_copy(c, z);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (size_t i = 0; i < ((size_t)1 << (w - 1)); i++) {
			MXP_FREE(tab[i]);
		}
		MXP_FREE(t);
		MXP_V_FREE(u);
		bn_free(z);
		RLC_FREE(win);
		RLC_FREE(tab);
	}
}

void bn_mxp_monty(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
	MXP_T tab[2], t;
	MXP_V u;
	bn_t z;
	int i, j;
#if BN_MOD == BN_MONTY
	size_t sm = m->used;
#endif

	if (bn_is_even(m)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (bn_is_zero(b)) {
		bn_set_dig(c, 1);
		return;
	}

	MXP_NULL(tab[0]);
	MXP_NULL(tab[1]);
	MXP_NULL(t);
	MXP_V_NULL(u);
	bn_null(z);

	RLC_TRY {
		MXP_V_NEW(u, m);
		MXP_NEW(tab[0], u);
		MXP_NEW(tab[1], u);
		MXP_NEW(t, u);
		bn_new(z);

#if BN_MOD == BN_MONTY
		bn_grow(t, 2 * sm);

		bn_set_dig(tab[0], 1);
		bn_mod_monty_conv(tab[0], tab[0], m);
		bn_mod_monty_conv(tab[1], a, m);

		bn_grow(tab[0], 2 * sm);
		bn_grow(tab[1], 2 * sm);
		dv_zero(tab[0]->dp + tab[0]->used, sm - tab[0]->used);
		dv_zero(tab[1]->dp + tab[1]->used, sm - tab[1]->used);

		/* Run over all digits of b and read its bits without branching, so
		 * that only the number of digits is revealed. Leading zeros leave
		 * the ladder unchanged. */
		for (i = RLC_DIG * b->used - 1; i >= 0; i--) {
			j = (b->dp[i / RLC_DIG] >> (i % RLC_DIG)) & 1;
			dv_swap_sec(tab[0]->dp, tab[1]->dp, sm, j ^ 1);
			bn_muln_low(t->dp, tab[0]->dp, tab[1]->dp, sm);
			bn_modn_low(tab[0]->dp, t->dp, 2 * sm, m->dp, sm, u->dp[0]);
			bn_sqrn_low(t->dp, tab[1]->dp, sm);
			bn_modn_low(tab[1]->dp, t->dp, 2 * sm, m->dp, sm, u->dp[0]);
			dv_swap_sec(tab[0]->dp, tab[1]->dp, sm, j ^ 1);
		}

		/* Convert back by reducing tab[0] < R, which leaves a value of at
		 * most m, then subtract m in constant time if it is not smaller. */
		dv_copy(t->dp, tab[0]->dp, sm);
		dv_zero(t->dp + sm, sm);
		bn_modn_low(tab[1]->dp, t->dp, 2 * sm, m->dp, sm, u->dp[0]);
		j = bn_subn_low(tab[0]->dp, tab[1]->dp, m->dp, sm);
		dv_copy_sec(tab[0]->dp, tab[1]->dp, sm, j);
		tab[0]->used = sm;
		tab[0]->sign = RLC_POS;
		bn_trim(tab[0]);
		bn_copy(z, tab[0]);
#else
		MXP_ONE(tab[0], m, u);
		MXP_CONV(tab[1], a, m, u);

		MXP_GROW(tab[0], m);
		MXP_GROW(tab[1], m);
		for (i = bn_bits(b) - 1; i >= 0; i--) {
			j = bn_get_bit(b, i);
			MXP_SWAP(tab[0], tab[1], j ^ 1, u);
			MXP_STEP(tab[0], tab[1], t, m, u);
			MXP_SWAP(tab[0], tab[1], j ^ 1, u);
		}

		MXP_BACK(z, tab[0], m, u);
#endif

		if (bn_sign(b) == RLC_NEG) {
			bn_mod_inv(c, z, m);
		} else {
			bn_copy(c, z);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		MXP_FREE(t);
		MXP_FREE(tab[1]);
		MXP_FREE(tab[0]);
		MXP_V_FREE(u);
		bn_free(z);
	}
}

#if BN_MXP == BN_LOWER

void bn_mxp_lower(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
	bn_t t, u;
	size_t sm;

	if (bn_is_even(m)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (bn_is_zero(b)) {
		bn_set_dig(c, 1);
		return;
	}

	if (bn_is_zero(a)) {
		bn_zero(c);
		return;
	}

	bn_null_all(t, u);

	RLC_TRY {
		bn_new_all(t, u);

		sm = m->used;
		bn_grow(u, sm);
		/* The low level takes the Montgomery constant whatever BN_MOD is. */
		bn_mod_pre_monty(u, m);
		bn_mod(t, a, m);
		dv_zero(t->dp + t->used, sm - t->used);

		bn_mxpn_low(u->dp, t->dp, sm, b->dp, b->used, m->dp, sm, u->dp[0]);
		u->used = sm;
		u->sign = RLC_POS;

		/* The base was reduced to [0, m), so its sign is already accounted. */
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
		bn_free_all(t, u);
	}
}

#endif

void bn_mxp_crt(bn_t d, const bn_t a, const bn_t b, const bn_t c,
		const crt_t crt, int sqr) {
	bn_t t, u;

	bn_null_all(t, u);

	RLC_TRY {
		bn_new_all(t, u);
#if BN_MOD == BN_RENUS
		/* Use the contexts of the moduli set, when it has them. */
		rns_hint(crt->rns, 2);
#endif

		/* The halves run in parallel under OpenMP, except in a Residue Number
		 * System, where both threads would update the shared cache. */
		if (!sqr) {
#if RLC_MULTI == RLC_OPENMP && BN_MOD != BN_RENUS
			omp_set_num_threads(RLC_CORES);
			#pragma omp parallel copyin(core_ctx) firstprivate(crt)
			{
				#pragma omp sections
				{
					#pragma omp section
					{
#endif
						/* m1 = a^dP mod p. */
						bn_mxp(t, a, b, crt->p);
#if RLC_MULTI == RLC_OPENMP && BN_MOD != BN_RENUS
					}
#pragma omp section
					{
#endif
						/* m2 = a^dQ mod q. */
						bn_mxp(u, a, c, crt->q);
#if RLC_MULTI == RLC_OPENMP && BN_MOD != BN_RENUS
					}
				}
			}
#endif
		} else {
#if RLC_MULTI == RLC_OPENMP && BN_MOD != BN_RENUS
			omp_set_num_threads(RLC_CORES);
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
#if RLC_MULTI == RLC_OPENMP && BN_MOD != BN_RENUS
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
#if RLC_MULTI == RLC_OPENMP && BN_MOD != BN_RENUS
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
#if BN_MOD == BN_RENUS
		rns_hint(NULL, 0);
#endif
		bn_free_all(t, u);
	}
}

void bn_mxp_crt_pre(crt_t crt, int sqr) {
#if BN_MOD == BN_RENUS
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		for (int k = 0; k < 2; k++) {
			bn_copy(t, (k == 0 ? crt->p : crt->q));
			if (sqr) {
				bn_sqr(t, t);
			}
			rns_free(&(crt->rns[k]));
			rns_new(&(crt->rns[k]), RLC_RNS_SIZE(bn_bits(t), BN_MXP_ROOM),
					t->used);
			if (crt->rns[k].mem != NULL) {
				rns_pre(&(crt->rns[k]), t, BN_MXP_ROOM);
			}
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
	}
#else
	(void)crt;
	(void)sqr;
#endif
}

void bn_mxp_dig(bn_t c, const bn_t a, dig_t b, const bn_t m) {
	int i, l;
	MXP_T r, t;
	MXP_V u;
	bn_t z;

	if (bn_is_even(m)) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (bn_cmp_dig(m, 1) == RLC_EQ) {
		bn_zero(c);
		return;
	}

	if (b == 0) {
		bn_set_dig(c, 1);
		return;
	}

	MXP_NULL(r);
	MXP_NULL(t);
	MXP_V_NULL(u);
	bn_null(z);

	RLC_TRY {
		MXP_V_NEW(u, m);
		MXP_NEW(r, u);
		MXP_NEW(t, u);
		bn_new(z);

		l = util_bits_dig(b);

		MXP_CONV(t, a, m, u);
		MXP_COPY(r, t, u);
		for (i = l - 2; i >= 0; i--) {
			MXP_SQR(r, r, m, u);
			if (b & ((dig_t)1 << i)) {
				MXP_MUL(r, r, t, m, u);
			}
		}
		MXP_BACK(z, r, m, u);

		/* Write c last, since it may alias m. The exponent is unsigned. */
		bn_copy(c, z);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		MXP_FREE(r);
		MXP_FREE(t);
		MXP_V_FREE(u);
		bn_free(z);
	}
}
