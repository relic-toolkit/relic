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
 * Implementation of the multiple precision integer modular reduction
 * functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_mod_2b(bn_t c, const bn_t a, int b) {
	int i, first, d;

	if (b <= 0) {
		bn_zero(c);
		return;
	}

	if (b >= (int)(a->used * RLC_DIG)) {
		bn_copy(c, a);
		return;
	}

	bn_copy(c, a);

	RLC_RIP(b, d, b);

	first = (d) + (b == 0 ? 0 : 1);
	for (i = first; i < c->used; i++) {
		c->dp[i] = 0;
	}

	c->dp[d] &= RLC_MASK(b);

	bn_trim(c);
}

void bn_mod_dig(dig_t *c, const bn_t a, dig_t b) {
	bn_div_rem_dig(NULL, c, a, b);
}

void bn_mod_basic(bn_t c, const bn_t a, const bn_t m) {
	bn_div_rem(NULL, c, a, m);
}

#if BN_MOD == BARRT || !defined(STRIP)

void bn_mod_pre_barrt(bn_t u, const bn_t m) {
	if (bn_sign(m) != RLC_POS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_set_2b(u, m->used * 2 * RLC_DIG);
	bn_div(u, u, m);
}

void bn_mod_barrt(bn_t c, const bn_t a, const bn_t m, const bn_t u) {
	bn_t q, t;
	int mu, neg;

	bn_null(q);
	bn_null(t);

	if (bn_sign(m) != RLC_POS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (bn_cmp_abs(a, m) == RLC_LT) {
		bn_copy(c, a);
		return;
	}

	if (a->used > 2 * m->used) {
		bn_mod(c, a, m);
		return;
	}

	RLC_TRY {
		bn_new(q);
		bn_new(t);
		bn_zero(t);

		neg = (bn_sign(a) == RLC_NEG);
		bn_abs(c, a);

		bn_rsh(q, c, (m->used - 1) * RLC_DIG);

		if (m->used > ((dig_t)1) << (RLC_DIG - 1)) {
			bn_mul(t, q, u);
		} else {
			bn_grow(t, q->used + u->used);
			if (q->used > u->used) {
				bn_muld_low(t->dp, q->dp, q->used, u->dp, u->used, m->used,
						q->used + u->used);
			} else {
				mu = RLC_MAX(0, m->used - (u->used - q->used));
				bn_muld_low(t->dp, u->dp, u->used, q->dp, q->used, mu,
						q->used + u->used);
			}
			t->used = q->used + u->used;
			bn_trim(t);
		}

		bn_rsh(q, t, (m->used + 1) * RLC_DIG);

		if (q->used > m->used) {
			bn_muld_low(t->dp, q->dp, q->used, m->dp, m->used, 0, q->used + 1);
		} else {
			bn_muld_low(t->dp, m->dp, m->used, q->dp, q->used, 0, m->used + 1);
		}
		t->used = m->used + 1;
		bn_trim(t);

		bn_mod_2b(q, t, RLC_DIG * (m->used + 1));
		bn_mod_2b(t, c, RLC_DIG * (m->used + 1));
		bn_sub(t, t, q);

		if (bn_sign(t) == RLC_NEG) {
			bn_set_dig(q, (dig_t)1);
			bn_lsh(q, q, (m->used + 1) * RLC_DIG);
			bn_add(t, t, q);
		}

		while (bn_cmp(t, m) != RLC_LT) {
			bn_sub(t, t, m);
		}

		bn_copy(c, t);
		if (neg) {
			bn_sub(c, m, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(q);
		bn_free(t);
	}
}

#endif /* BN_MOD == BARRT || !defined(STRIP) */

#if BN_MOD == MONTY || (defined(WITH_FP) && FP_RDC == MONTY) || !defined(STRIP)

void bn_mod_pre_monty(bn_t u, const bn_t m) {
	dig_t x, b = m->dp[0];

	if (bn_is_even(m) || bn_sign(m) != RLC_POS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	x = (((b + 2) & 4) << 1) + b;				/* here x*a==1 mod 2**4 */
	x *= (dig_t)2 - b * x;						/* here x*a==1 mod 2**8 */
#if WSIZE > 8
	x *= (dig_t)2 - b * x;						/* here x*a==1 mod 2**16 */
#endif
#if WSIZE > 16
	x *= (dig_t)2 - b * x;						/* here x*a==1 mod 2**32 */
#endif
#if WSIZE > 32
	x *= (dig_t)2 - b * x;						/* here x*a==1 mod 2**64 */
#endif
	/* u = -1/m0 (mod 2^RLC_DIG) */
	bn_set_dig(u, -x);
}

void bn_mod_monty_conv(bn_t c, const bn_t a, const bn_t m) {
	if (bn_is_even(m) || bn_sign(m) != RLC_POS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_mod(c, a, m);
	bn_lsh(c, c, m->used * RLC_DIG);
	bn_mod(c, c, m);
}

void bn_mod_monty_back(bn_t c, const bn_t a, const bn_t m) {
	bn_t u;

	bn_null(u);

	RLC_TRY {
		bn_new(u);
		bn_mod_pre_monty(u, m);
		bn_mod_monty(c, a, m, u);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(u);
	}
}

#if BN_MUL == BASIC || !defined(STRIP)

void bn_mod_monty_basic(bn_t c, const bn_t a, const bn_t m, const bn_t u) {
	int digits, i;
	dig_t r, u0, *tmp;
	bn_t t;

	bn_null(t);
	digits = 2 * m->used;

	RLC_TRY {
		bn_new_size(t, digits);
		bn_zero(t);
		bn_copy(t, a);

		u0 = u->dp[0];
		tmp = t->dp;

		for (i = 0; i < m->used; i++, tmp++) {
			r = (dig_t)(*tmp * u0);
			*tmp = bn_mula_low(tmp, m->dp, r, m->used);
		}
		if (bn_addn_low(t->dp, t->dp, tmp, m->used)) {
			bn_subn_low(t->dp, t->dp, m->dp, m->used);
		}
		t->used = m->used;
		bn_trim(t);

		if (bn_cmp_abs(t, m) != RLC_LT) {
			bn_sub(t, t, m);
		}

		bn_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

#endif /* BN_MUL == BASIC || !defined(STRIP) */

#if BN_MUL == COMBA || !defined(STRIP)

void bn_mod_monty_comba(bn_t c, const bn_t a, const bn_t m, const bn_t u) {
	int digits;
	bn_t t;

	bn_null(t);
	digits = 2 * m->used;

	RLC_TRY {
		bn_new_size(t, digits);
		bn_zero(t);

		bn_modn_low(t->dp, a->dp, a->used, m->dp, m->used, u->dp[0]);
		t->used = m->used;

		bn_trim(t);
		if (bn_cmp_abs(t, m) != RLC_LT) {
			bn_sub(t, t, m);
		}
		bn_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

#endif /* BN_MUL == COMBA || !defined(STRIP) */

#endif /* BN_MOD == MONTY || (WITH_FP && FP_RDC == MONTY) || !defined(STRIP) */

#if BN_MOD == PMERS || !defined(STRIP)

void bn_mod_pre_pmers(bn_t u, const bn_t m) {
	if (bn_sign(m) != RLC_POS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_set_2b(u, bn_bits(m));
	bn_sub(u, u, m);
}

void bn_mod_pmers(bn_t c, const bn_t a, const bn_t m, const bn_t u) {
	bn_t q, t;
	int neg = 0, bits = bn_bits(m);

	if (bn_sign(m) != RLC_POS) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	bn_null(q);
	bn_null(t);

	RLC_TRY {
		/* Implement algorithm 10.25 from HEHC. */

		bn_new(q);
		bn_new(t);

		bn_copy(c, a);
		if (bn_sign(c) == RLC_NEG) {
			neg = 1;
			bn_sub(c, m, c);
		}

		bn_rsh(q, c, bits);
		bn_mod_2b(c, c, bits);

		while (bits > 0 && !bn_is_zero(q)) {
			if (u -> used == 1) {
				bn_mul_dig(t, q, u->dp[0]);
			} else {
				bn_mul(t, q, u);
			}
			bn_rsh(q, t, bits);
			bn_mod_2b(t, t, bits);

			bn_add(c, c, t);
		}
		while (bits > 0 && bn_cmp_abs(c, m) != RLC_LT) {
			bn_sub(c, c, m);
		}

		if (neg) {
			bn_sub(c, m, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(q);
	}
}

#endif /* BN_MOD == PMERS || !defined(STRIP) */
