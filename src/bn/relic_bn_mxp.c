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

#if BN_MOD == BN_MONTY

/**
 * Exponentiates by the Montgomery powering ladder in Montgomery form, on the
 * digits of the low level, so that with the gmp-sec backend it runs in
 * constant time in the exponent.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 * @param[in] m				- the modulus.
 * @param[in] u				- the Montgomery constant of the modulus.
 */
static void bn_mxp_monty_pos(bn_t c, const bn_t a, const bn_t b, const bn_t m,
		const bn_t u) {
	bn_t tab[2], t, z;
	int i, j;
	size_t sm = m->used;

	bn_null_all(tab[0], tab[1], t, z);

	RLC_TRY {
		bn_new_all(tab[0], tab[1], t, z);

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
		bn_free_all(t, tab[1], tab[0], z);
	}
}

#else

TMPL_BN_MXP_MONTY(pos, MXP_POS)

#endif

TMPL_BN_MXP_BASIC(pos, MXP_POS)
TMPL_BN_MXP_SLIDE(pos, MXP_POS)
TMPL_BN_MXP_LWREG(pos, MXP_POS)
TMPL_BN_MXP_DIG(pos, MXP_POS)

#if BN_MOD == BN_RENUS
TMPL_BN_MXP_BASIC(rns, MXP_RNS)
TMPL_BN_MXP_SLIDE(rns, MXP_RNS)
TMPL_BN_MXP_MONTY(rns, MXP_RNS)
TMPL_BN_MXP_LWREG(rns, MXP_RNS)
TMPL_BN_MXP_DIG(rns, MXP_RNS)
#endif

/**
 * Reduces a digit vector t below m * R, for R = 2^(RLC_DIG * s), by
 * Montgomery's algorithm and without branches: c = t / R mod m, in [0, m).
 *
 * @param[out] c			- the s digits of the result.
 * @param[in] t				- the 2s digits to reduce.
 * @param[in] m				- the s digits of the modulus.
 * @param[in] s				- the number of digits of the modulus.
 * @param[in] u				- the Montgomery constant -m^{-1} mod 2^RLC_DIG.
 */
static void bn_crt_rdc(dig_t *c, const dig_t *t, const dig_t *m, size_t s,
		dig_t u) {
	dig_t w[RLC_BN_SIZE], v[RLC_BN_DIGS], b;

	/* The low level may work in place over all digits of t. */
	bn_modn_low(w, t, 2 * s, m, s, u);
	/* The result is below 2m, so one subtraction of m reduces it. */
	b = bn_subn_low(v, w, m, s);
	dv_copy_sec(v, w, s, b);
	dv_copy(c, v, s);
}

/**
 * Finishes a modular exponentiation by the Chinese Remainder Theorem from its
 * halves. When the moduli have the same number of digits, the values derived
 * from the secret halves are only handled by arithmetic without branches.
 *
 * @param[out] d			- the result.
 * @param[in,out] t			- the half modulo p, or modulo p^2 if sqr is set.
 * @param[in,out] u			- the half modulo q, or modulo q^2 if sqr is set.
 * @param[in] crt			- the set of moduli.
 * @param[in] sqr			- the flag to indicate if modulo n or n^2.
 */
static void bn_mxp_crt_fin(bn_t d, bn_t t, bn_t u, const crt_t crt, int sqr) {
	const size_t s = crt->p->used;
	dig_t x[RLC_BN_SIZE], y[RLC_BN_SIZE], one[RLC_BN_SIZE];
	dig_t mp[RLC_BN_DIGS], mq[RLC_BN_DIGS], rp[RLC_BN_DIGS], qr[RLC_BN_DIGS];
	dig_t hp[RLC_BN_DIGS], hq[RLC_BN_DIGS], ip[RLC_BN_DIGS], iq[RLC_BN_DIGS];
	dig_t up, uq, b;
	bn_t z, w;

	if (crt->q->used != s || s > RLC_BN_DIGS || t->used > 2 * s ||
			u->used > 2 * s) {
		/* Moduli of different lengths take the variable-time path. */
		if (sqr) {
			/* m_p = L(t) * dp mod p and m_q = L(u) * dq mod q. */
			bn_sub_dig(t, t, 1);
			bn_div(t, t, crt->p);
			bn_mul(t, t, crt->dp);
			bn_mod(t, t, crt->p);
			bn_sub_dig(u, u, 1);
			bn_div(u, u, crt->q);
			bn_mul(u, u, crt->dq);
			bn_mod(u, u, crt->q);
		}
		/* m = m_q + q * (qInv * (m_p - m_q) mod p). */
		bn_sub(d, t, u);
		while (bn_sign(d) == RLC_NEG) {
			bn_add(d, d, crt->p);
		}
		bn_mul(d, d, crt->qi);
		bn_mod(d, d, crt->p);
		bn_mul(d, d, crt->q);
		bn_add(d, d, u);
		return;
	}

	bn_null_all(z, w);

	RLC_TRY {
		bn_new_all(z, w);

		/* Constants of the key, whose computation depends on it alone. */
		bn_mod_pre_monty(z, crt->p);
		up = z->dp[0];
		bn_mod_pre_monty(z, crt->q);
		uq = z->dp[0];
		/* R mod p and qInv * R mod p, for R = 2^(RLC_DIG * s). */
		bn_set_2b(z, RLC_DIG * s);
		bn_mod(z, z, crt->p);
		dv_zero(rp, s);
		dv_copy(rp, z->dp, z->used);
		bn_lsh(z, crt->qi, RLC_DIG * s);
		bn_mod(z, z, crt->p);
		dv_zero(qr, s);
		dv_copy(qr, z->dp, z->used);

		dv_zero(one, 2 * s);
		one[0] = 1;
		dv_zero(mp, s);
		dv_zero(mq, s);
		if (sqr) {
			/* dp * R mod p, dq * R mod q, and the inverses of p and q. */
			bn_lsh(z, crt->dp, RLC_DIG * s);
			bn_mod(z, z, crt->p);
			dv_zero(hp, s);
			dv_copy(hp, z->dp, z->used);
			bn_lsh(z, crt->dq, RLC_DIG * s);
			bn_mod(z, z, crt->q);
			dv_zero(hq, s);
			dv_copy(hq, z->dp, z->used);
			bn_set_2b(w, RLC_DIG * s);
			bn_mod_inv(z, crt->p, w);
			dv_zero(ip, s);
			dv_copy(ip, z->dp, z->used);
			bn_mod_inv(z, crt->q, w);
			dv_zero(iq, s);
			dv_copy(iq, z->dp, z->used);

			/* t - 1 = p * L(t) exactly, so L(t) = (t - 1) / p mod R, and
			 * then m_p = L(t) * dp mod p. The same holds modulo q. */
			dv_zero(x, 2 * s);
			dv_copy(x, t->dp, t->used);
			bn_subn_low(x, x, one, 2 * s);
			bn_muln_low(y, x, ip, s);
			bn_muln_low(x, y, hp, s);
			bn_crt_rdc(mp, x, crt->p->dp, s, up);
			dv_zero(x, 2 * s);
			dv_copy(x, u->dp, u->used);
			bn_subn_low(x, x, one, 2 * s);
			bn_muln_low(y, x, iq, s);
			bn_muln_low(x, y, hq, s);
			bn_crt_rdc(mq, x, crt->q->dp, s, uq);
		} else {
			dv_copy(mp, t->dp, t->used);
			dv_copy(mq, u->dp, u->used);
		}

		/* h = (m_p - m_q mod p) mod p, where m_q mod p = m_q * R / R. */
		bn_muln_low(x, mq, rp, s);
		bn_crt_rdc(hq, x, crt->p->dp, s, up);
		b = bn_subn_low(hp, mp, hq, s);
		bn_addn_low(x, hp, crt->p->dp, s);
		dv_copy_sec(hp, x, s, b);
		/* h = h * qInv mod p and m = m_q + q * h. */
		bn_muln_low(x, hp, qr, s);
		bn_crt_rdc(hp, x, crt->p->dp, s, up);
		bn_muln_low(x, crt->q->dp, hp, s);
		dv_zero(y, 2 * s);
		dv_copy(y, mq, s);
		bn_addn_low(x, x, y, 2 * s);

		bn_grow(d, 2 * s);
		dv_copy(d->dp, x, 2 * s);
		d->used = 2 * s;
		d->sign = RLC_POS;
		bn_trim(d);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(z, w);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_mxp_basic(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
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

	BN_MXP_RUN(bn_mxp_basic, m, bn_bits(b), c, a, b, m);
}

void bn_mxp_slide(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
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

	if (bn_bits(b) < BN_MXP_BITS) {
		/* The binary method is the faster of the two while the exponent is
		 * too short to pay for the table of the window. */
		BN_MXP_RUN(bn_mxp_basic, m, bn_bits(b), c, a, b, m);
	} else {
		BN_MXP_RUN(bn_mxp_slide, m, bn_bits(b), c, a, b, m);
	}
}

void bn_mxp_monty(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
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

	BN_MXP_RUN(bn_mxp_monty, m, bn_bits(b), c, a, b, m);
}

void bn_mxp_lwreg(bn_t c, const bn_t a, const bn_t b, const bn_t m) {
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

	BN_MXP_RUN(bn_mxp_lwreg, m, bn_bits(b), c, a, b, m);
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
						/* t = c^(p-1) mod p^2. */
						bn_sqr(t, crt->p);
						bn_mxp(t, a, b, t);
#if RLC_MULTI == RLC_OPENMP && BN_MOD != BN_RENUS
					}
					#pragma omp section
					{
#endif
						/* u = c^(q-1) mod q^2. */
						bn_sqr(u, crt->q);
						bn_mxp(u, a, c, u);
#if RLC_MULTI == RLC_OPENMP && BN_MOD != BN_RENUS
					}
				}
			}
#endif
		}
		bn_mxp_crt_fin(d, t, u, crt, sqr);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
#if BN_MOD == BN_RENUS
		rns_hint(NULL, 0);
#endif
		bn_free_all(t, u);
	}
}

void bn_mxp_dig(bn_t c, const bn_t a, dig_t b, const bn_t m) {
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

	BN_MXP_RUN(bn_mxp_dig, m, util_bits_dig(b), c, a, b, m);
}
