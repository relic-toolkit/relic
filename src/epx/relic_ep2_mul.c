/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of point multiplication on prime elliptic curves over
 * quadratic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_MUL == LWNAF || !defined(STRIP)

#if defined(EP_ENDOM)

static void ep2_mul_gls_imp(ep2_t r, const ep2_t p, const bn_t k) {
	size_t l, _l[4];
	bn_t n, _k[4], u;
	int8_t naf[4][RLC_FP_BITS + 1];
	ep2_t q[4];

	bn_null(n);
	bn_null(u);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (int i = 0; i < 4; i++) {
			bn_null(_k[i]);
			ep2_null(q[i]);
			bn_new(_k[i]);
			ep2_new(q[i]);
		}

		ep2_curve_get_ord(n);
		fp_prime_get_par(u);
		bn_mod(_k[0], k, n);
		bn_rec_frb(_k, 4, _k[0], u, n, ep_curve_is_pairf() == EP_BN);

		ep2_norm(q[0], p);
		ep2_frb(q[1], q[0], 1);
		ep2_frb(q[2], q[1], 1);
		ep2_frb(q[3], q[2], 1);

		l = 0;
		for (int i = 0; i < 4; i++) {
			if (bn_sign(_k[i]) == RLC_NEG) {
				ep2_neg(q[i], q[i]);
			}
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _k[i], 2);
			l = RLC_MAX(l, _l[i]);
		}

		ep2_set_infty(r);
		for (int j = l - 1; j >= 0; j--) {
			ep2_dbl(r, r);

			for (int i = 0; i < 4; i++) {
				if (naf[i][j] > 0) {
					ep2_add(r, r, q[i]);
				}
				if (naf[i][j] < 0) {
					ep2_sub(r, r, q[i]);
				}
			}
		}

		/* Convert r to affine coordinates. */
		ep2_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		for (int i = 0; i < 4; i++) {
			bn_free(_k[i]);
			ep2_free(q[i]);
		}

	}
}

#endif /* EP_ENDOM */

#if defined(EP_PLAIN) || defined(EP_SUPER)

static void ep2_mul_naf_imp(ep2_t r, const ep2_t p, const bn_t k) {
	size_t l;
	int8_t n, naf[RLC_FP_BITS + 1];
	ep2_t t[1 << (RLC_WIDTH - 2)];

	RLC_TRY {
		/* Prepare the precomputation table. */
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep2_null(t[i]);
			ep2_new(t[i]);
		}
		/* Compute the precomputation table. */
		ep2_tab(t, p, RLC_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = sizeof(naf);
		bn_rec_naf(naf, &l, k, RLC_WIDTH);

		ep2_set_infty(r);
		for (int i = l - 1; i >= 0; i--) {
			ep2_dbl(r, r);

			n = naf[i];
			if (n > 0) {
				ep2_add(r, r, t[n / 2]);
			}
			if (n < 0) {
				ep2_sub(r, r, t[-n / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ep2_norm(r, r);
		if (bn_sign(k) == RLC_NEG) {
			ep2_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation table. */
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep2_free(t[i]);
		}
	}
}

#endif /* EP_PLAIN || EP_SUPER */
#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

#if defined(EP_ENDOM)

static void ep2_mul_reg_gls(ep2_t r, const ep2_t p, const bn_t k) {
	size_t l, _l[4];
	bn_t n, _k[4], u;
	int8_t reg[4][RLC_FP_BITS + 1], b[4], s[4], c0, c1;
	ep2_t q[4], t;

	bn_null(n);
	bn_null(u);
	ep2_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (int i = 0; i < 4; i++) {
			bn_null(_k[i]);
			ep2_null(q[i]);
			bn_new(_k[i]);
			ep2_new(q[i]);
		}
		ep2_new(t);

		ep2_curve_get_ord(n);
		fp_prime_get_par(u);
		bn_mod(_k[0], k, n);
		bn_rec_frb(_k, 4, _k[0], u, n, ep_curve_is_pairf() == EP_BN);

		ep2_norm(q[0], p);
		ep2_frb(q[1], q[0], 1);
		ep2_frb(q[2], q[1], 1);
		ep2_frb(q[3], q[2], 1);

		l = 0;
		for (int i = 0; i < 4; i++) {
			s[i] = bn_sign(_k[i]);
			bn_abs(_k[i], _k[i]);
			b[i] = bn_is_even(_k[i]);
			_k[i]->dp[0] |= b[i];

			/* Make some extra room for BN curves that grow subscalars by 1. */
			l = bn_bits(u) + (ep_curve_is_pairf() == EP_BN);
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_reg(reg[i], &_l[i], _k[i], l, 2);
			l = RLC_MAX(l, _l[i]);
		}

		ep2_set_infty(r);
		for (int j = l - 1; j >= 0; j--) {
			ep2_dbl(r, r);

			for (int i = 0; i < 4; i++) {
				c0 = reg[i][j] > 0;
				c1 = s[i] == RLC_POS;

				ep2_neg(t, q[i]);
				dv_copy_cond(t->y[0], q[i]->y[0], RLC_FP_DIGS, c0 == c1);
				dv_copy_cond(t->y[1], q[i]->y[1], RLC_FP_DIGS, c0 == c1);
				ep2_add(r, r, t);
			}
		}

		for (int i = 0; i < 4; i++) {
			ep2_neg(t, q[i]);
			dv_copy_cond(t->y[0], q[i]->y[0], RLC_FP_DIGS, s[i] == RLC_NEG);
			dv_copy_cond(t->y[1], q[i]->y[1], RLC_FP_DIGS, s[i] == RLC_NEG);
			ep2_add(t, r, t);
			dv_copy_cond(r->x[0], t->x[0], RLC_FP_DIGS, b[i]);
			dv_copy_cond(r->x[1], t->x[1], RLC_FP_DIGS, b[i]);
			dv_copy_cond(r->y[0], t->y[0], RLC_FP_DIGS, b[i]);
			dv_copy_cond(r->y[1], t->y[1], RLC_FP_DIGS, b[i]);
			dv_copy_cond(r->z[0], t->z[0], RLC_FP_DIGS, b[i]);
			dv_copy_cond(r->z[1], t->z[1], RLC_FP_DIGS, b[i]);
		}

		/* Convert r to affine coordinates. */
		ep2_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		for (int i = 0; i < 4; i++) {
			bn_free(_k[i]);
			ep2_free(q[i]);
		}
		ep2_free(t);
	}
}

#endif /* EP_ENDOM */

#if defined(EP_PLAIN) || defined(EP_SUPER)

static void ep2_mul_reg_imp(ep2_t r, const ep2_t p, const bn_t k) {
	bn_t _k;
	int i, j, n;
	int8_t s, reg[1 + RLC_CEIL(RLC_FP_BITS + 1, RLC_WIDTH - 1)];
	ep2_t t[1 << (RLC_WIDTH - 2)], u, v;
	size_t l;

	bn_null(_k);

	RLC_TRY {
		bn_new(_k);
		ep2_new(u);
		ep2_new(v);
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep2_null(t[i]);
			ep2_new(t[i]);
		}
		/* Compute the precomputation table. */
		ep2_tab(t, p, RLC_WIDTH);

		ep2_curve_get_ord(_k);
		n = bn_bits(_k);

		/* Make a copy of the scalar for processing. */
		bn_abs(_k, k);
		_k->dp[0] |= 1;

		/* Compute the regular w-NAF representation of k. */
		l = RLC_CEIL(n, RLC_WIDTH - 1) + 1;
		bn_rec_reg(reg, &l, _k, n, RLC_WIDTH);

#if defined(EP_MIXED)
		fp2_set_dig(u->z, 1);
		u->coord = BASIC;
#else
		u->coord = EP_ADD;
#endif
		ep2_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			for (j = 0; j < RLC_WIDTH - 1; j++) {
				ep2_dbl(r, r);
			}

			n = reg[i];
			s = (n >> 7);
			n = ((n ^ s) - s) >> 1;

			for (j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {
				dv_copy_cond(u->x[0], t[j]->x[0], RLC_FP_DIGS, j == n);
				dv_copy_cond(u->x[1], t[j]->x[1], RLC_FP_DIGS, j == n);
				dv_copy_cond(u->y[0], t[j]->y[0], RLC_FP_DIGS, j == n);
				dv_copy_cond(u->y[1], t[j]->y[1], RLC_FP_DIGS, j == n);
#if !defined(EP_MIXED)
				dv_copy_cond(u->z[0], t[j]->z[0], RLC_FP_DIGS, j == n);
				dv_copy_cond(u->z[1], t[j]->z[1], RLC_FP_DIGS, j == n);
#endif
			}
			ep2_neg(v, u);
			dv_copy_cond(u->y[0], v->y[0], RLC_FP_DIGS, s != 0);
			dv_copy_cond(u->y[1], v->y[1], RLC_FP_DIGS, s != 0);
			ep2_add(r, r, u);
		}
		/* t[0] has an unmodified copy of p. */
		ep2_sub(u, r, t[0]);
		dv_copy_cond(r->x[0], u->x[0], RLC_FP_DIGS, bn_is_even(k));
		dv_copy_cond(r->x[1], u->x[1], RLC_FP_DIGS, bn_is_even(k));
		dv_copy_cond(r->y[0], u->y[0], RLC_FP_DIGS, bn_is_even(k));
		dv_copy_cond(r->y[1], u->y[1], RLC_FP_DIGS, bn_is_even(k));
		dv_copy_cond(r->z[0], u->z[0], RLC_FP_DIGS, bn_is_even(k));
		dv_copy_cond(r->z[1], u->z[1], RLC_FP_DIGS, bn_is_even(k));
		/* Convert r to affine coordinates. */
		ep2_norm(r, r);
		ep2_neg(u, r);
		dv_copy_cond(r->y[0], u->y[0], RLC_FP_DIGS, bn_sign(k) == RLC_NEG);
		dv_copy_cond(r->y[1], u->y[1], RLC_FP_DIGS, bn_sign(k) == RLC_NEG);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep2_free(t[i]);
		}
		bn_free(_k);
		ep2_free(u);
		ep2_free(v);
	}
}

#endif /* EP_PLAIN || EP_SUPER */
#endif /* EP_MUL == LWREG */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep2_mul_basic(ep2_t r, const ep2_t p, const bn_t k) {
	ep2_t t;
	int8_t u, *naf = RLC_ALLOCA(int8_t, bn_bits(k) + 1);
	size_t l;

	ep2_null(t);

	if (bn_is_zero(k) || ep2_is_infty(p)) {
		RLC_FREE(naf);
		ep2_set_infty(r);
		return;
	}

	if (bn_bits(k) <= RLC_DIG) {
		ep2_mul_dig(r, p, k->dp[0]);
		if (bn_sign(k) == RLC_NEG) {
			ep2_neg(r, r);
		}
		RLC_FREE(naf);
		return;
	}

	RLC_TRY {
		ep2_new(t);
		if (naf == NULL) {
			RLC_THROW(ERR_NO_BUFFER);
		}

		l = bn_bits(k) + 1;
		bn_rec_naf(naf, &l, k, 2);
		ep2_set_infty(t);
		for (int i = l - 1; i >= 0; i--) {
			ep2_dbl(t, t);

			u = naf[i];
			if (u > 0) {
				ep2_add(t, t, p);
			} else if (u < 0) {
				ep2_sub(t, t, p);
			}
		}

		ep2_norm(r, t);
		if (bn_sign(k) == RLC_NEG) {
			ep2_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(t);
		RLC_FREE(naf);
	}
}

#if EP_MUL == SLIDE || !defined(STRIP)

void ep2_mul_slide(ep2_t r, const ep2_t p, const bn_t k) {
	ep2_t t[1 << (RLC_WIDTH - 1)], q;
	uint8_t win[RLC_FP_BITS + 1];
	size_t l;

	ep2_null(q);

	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	RLC_TRY {
		for (int i = 0; i < (1 << (RLC_WIDTH - 1)); i ++) {
			ep2_null(t[i]);
			ep2_new(t[i]);
		}

		ep2_new(q);

		ep2_copy(t[0], p);
		ep2_dbl(q, p);

#if defined(EP_MIXED)
		ep2_norm(q, q);
#endif

		/* Create table. */
		for (size_t i = 1; i < (1 << (RLC_WIDTH - 1)); i++) {
			ep2_add(t[i], t[i - 1], q);
		}

#if defined(EP_MIXED)
		ep2_norm_sim(t + 1, t + 1, (1 << (RLC_WIDTH - 1)) - 1);
#endif

		ep2_set_infty(q);
		l = RLC_FP_BITS + 1;
		bn_rec_slw(win, &l, k, RLC_WIDTH);
		for (size_t i = 0; i < l; i++) {
			if (win[i] == 0) {
				ep2_dbl(q, q);
			} else {
				for (size_t j = 0; j < util_bits_dig(win[i]); j++) {
					ep2_dbl(q, q);
				}
				ep2_add(q, q, t[win[i] >> 1]);
			}
		}

		ep2_norm(r, q);
		if (bn_sign(k) == RLC_NEG) {
			ep2_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 1)); i++) {
			ep2_free(t[i]);
		}
		ep2_free(q);
	}
}

#endif

#if EP_MUL == MONTY || !defined(STRIP)

void ep2_mul_monty(ep2_t r, const ep2_t p, const bn_t k) {
	ep2_t t[2];
	bn_t n, l, _k;
	size_t bits;

	bn_null(n);
	bn_null(l);
	bn_null(_k);
	ep2_null(t[0]);
	ep2_null(t[1]);

	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(l);
		bn_new(_k);
		ep2_new(t[0]);
		ep2_new(t[1]);

		ep2_curve_get_ord(n);
		bits = bn_bits(n);

		bn_mod(_k, k, n);
		bn_abs(l, _k);
		bn_add(l, l, n);
		bn_add(n, l, n);
		dv_swap_cond(l->dp, n->dp, RLC_MAX(l->used, n->used),
			bn_get_bit(l, bits) == 0);
		l->used = RLC_SEL(l->used, n->used, bn_get_bit(l, bits) == 0);

		ep2_norm(t[0], p);
		ep2_dbl(t[1], t[0]);

		/* Blind both points independently. */
		ep2_blind(t[0], t[0]);
		ep2_blind(t[1], t[1]);

		for (int i = bits - 1; i >= 0; i--) {
			int j = bn_get_bit(l, i);
			dv_swap_cond(t[0]->x[0], t[1]->x[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->x[1], t[1]->x[1], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y[0], t[1]->y[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y[1], t[1]->y[1], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z[0], t[1]->z[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z[1], t[1]->z[1], RLC_FP_DIGS, j ^ 1);
			ep2_add(t[0], t[0], t[1]);
			ep2_dbl(t[1], t[1]);
			dv_swap_cond(t[0]->x[0], t[1]->x[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->x[1], t[1]->x[1], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y[0], t[1]->y[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y[1], t[1]->y[1], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z[0], t[1]->z[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z[1], t[1]->z[1], RLC_FP_DIGS, j ^ 1);
		}

		ep2_norm(r, t[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(l);
		bn_free(_k);
		ep2_free(t[1]);
		ep2_free(t[0]);
	}
}

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep2_mul_lwnaf(ep2_t r, const ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		ep2_mul_gls_imp(r, p, k);
		return;
	}
#endif

#if defined(EP_PLAIN) || defined(EP_SUPER)
	ep2_mul_naf_imp(r, p, k);
#endif
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep2_mul_lwreg(ep2_t r, const ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		ep2_mul_reg_gls(r, p, k);
		return;
	}
#endif

#if defined(EP_PLAIN) || defined(EP_SUPER)
	ep2_mul_reg_imp(r, p, k);
#endif
}

#endif

void ep2_mul_gen(ep2_t r, const bn_t k) {
	if (bn_is_zero(k)) {
		ep2_set_infty(r);
		return;
	}

#ifdef EP_PRECO
	ep2_mul_fix(r, ep2_curve_get_tab(), k);
#else
	ep2_t g;

	ep2_null(g);

	RLC_TRY {
		ep2_new(g);
		ep2_curve_get_gen(g);
		ep2_mul(r, g, k);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(g);
	}
#endif
}

void ep2_mul_dig(ep2_t r, const ep2_t p, const dig_t k) {
	ep2_t t;
	bn_t _k;
	int8_t u, naf[RLC_DIG + 1];
	size_t l;

	ep2_null(t);
	bn_null(_k);

	if (k == 0 || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	RLC_TRY {
		ep2_new(t);
		bn_new(_k);

		bn_set_dig(_k, k);

		l = RLC_DIG + 1;
		bn_rec_naf(naf, &l, _k, 2);

		ep2_copy(t, p);
		for (int i = l - 2; i >= 0; i--) {
			ep2_dbl(t, t);

			u = naf[i];
			if (u > 0) {
				ep2_add(t, t, p);
			} else if (u < 0) {
				ep2_sub(t, t, p);
			}
		}

		ep2_norm(r, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(t);
		bn_free(_k);
	}
}
