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
 * Implementation of the point multiplication on prime elliptic curves.
 *
 * @ingroup eb
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_MUL == LWNAF || !defined(STRIP)

#if defined(EP_ENDOM)

static void ep_mul_glv_imp(ep_t r, const ep_t p, const bn_t k) {
	int i, n0, n1, s0, s1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *t0, *t1;
	bn_t n, m, k0, k1;
	ep_t q, t[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	bn_null(n);
	bn_null(m);
	bn_null(k0);
	bn_null(k1);
	ep_null(q);

	RLC_TRY {
		bn_new(n);
		bn_new(m);
		bn_new(k0);
		bn_new(k1);
		ep_new(q);
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep_null(t[i]);
			ep_new(t[i]);
		}

		ep_curve_get_ord(n);
		bn_mod(m, k, n);
		bn_rec_glv(k0, k1, m, n, ep_curve_get_v1(), ep_curve_get_v2());
		s0 = bn_sign(k0);
		s1 = bn_sign(k1);

		if (s0 == RLC_POS) {
			ep_tab(t, p, RLC_WIDTH);
		} else {
			ep_neg(q, p);
			ep_tab(t, q, RLC_WIDTH);
		}

		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, k0, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, k1, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		t0 = naf0 + l - 1;
		t1 = naf1 + l - 1;

		ep_set_infty(r);
		for (i = l - 1; i >= 0; i--, t0--, t1--) {
			ep_dbl(r, r);

			n0 = *t0;
			n1 = *t1;
			if (n0 > 0) {
				ep_add(r, r, t[n0 / 2]);
			}
			if (n0 < 0) {
				ep_sub(r, r, t[-n0 / 2]);
			}
			if (n1 > 0) {
				ep_psi(q, t[n1 / 2]);
				if (s0 != s1) {
					ep_neg(q, q);
				}
				ep_add(r, r, q);
			}
			if (n1 < 0) {
				ep_psi(q, t[-n1 / 2]);
				if (s0 != s1) {
					ep_neg(q, q);
				}
				ep_sub(r, r, q);
			}
		}
		/* Convert r to affine coordinates. */
		ep_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(m);
		bn_free(k0);
		bn_free(k1);
		bn_free(n)
		ep_free(q);
		for (i = 0; i < 1 << (RLC_WIDTH - 2); i++) {
			ep_free(t[i]);
		}
	}
}

#endif /* EP_ENDOM */

#if defined(EP_PLAIN) || defined(EP_SUPER)

static void ep_mul_naf_imp(ep_t r, const ep_t p, const bn_t k) {
	/* Some of the supported prime curves have order > field. */
	int8_t u, naf[RLC_FP_BITS + 2];
	ep_t t[1 << (RLC_WIDTH - 2)];
	bn_t m, n;
	size_t l;

	bn_null(n);
	bn_null(m);

	RLC_TRY {
		bn_new(n);
		bn_new(m);
		/* Prepare the precomputation table. */
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep_null(t[i]);
			ep_new(t[i]);
		}

		ep_curve_get_ord(n);
		bn_mod(m, k, n);

		/* Compute the precomputation table. */
		ep_tab(t, p, RLC_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = RLC_FP_BITS + 2;
		bn_rec_naf(naf, &l, m, RLC_WIDTH);

		ep_set_infty(r);
		for (int i = l - 1; i >= 0; i--) {
			ep_dbl(r, r);

			u = naf[i];
			if (u > 0) {
				ep_add(r, r, t[u / 2]);
			} else if (u < 0) {
				ep_sub(r, r, t[-u / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ep_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(m);
		/* Free the precomputation table. */
		for (int i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep_free(t[i]);
		}
	}
}

#endif /* EP_PLAIN || EP_SUPER */
#endif /* EP_MUL == LWNAF */

#if defined(EP_ENDOM)

static void ep_mul_reg_glv(ep_t r, const ep_t p, const bn_t k) {
	int8_t reg[2][RLC_FP_BITS + 1], s[2], b[2], c0, c1, n0, n1;
	bn_t n, m[2];
	ep_t q, t[1 << (RLC_WIDTH - 2)], u, w;
	size_t l;

	bn_null(n);
	bn_null(m[0]);
	bn_null(m[1]);
	ep_null(q);
	ep_null(u);
	ep_null(w);

	RLC_TRY {
		bn_new(n);
		bn_new(m[0]);
		bn_new(m[1]);
		ep_new(q);
		ep_new(u);
		ep_new(w);

		for (size_t i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep_null(t[i]);
			ep_new(t[i]);
		}

		ep_curve_get_ord(n);
		bn_mod(m[0], k, n);
		bn_rec_glv(m[0], m[1], m[0], n, ep_curve_get_v1(), ep_curve_get_v2());
		for (size_t i = 0; i < 2; i++) {
			s[i] = bn_sign(m[i]);
			bn_abs(m[i], m[i]);
			b[i] = bn_is_even(m[i]);
			m[i]->dp[0] |= b[i];
		}

		ep_norm(t[0], p);
		ep_neg(q, t[0]);
		dv_copy_sec(q->y, t[0]->y, RLC_FP_DIGS, s[0] == RLC_POS);
		ep_tab(t, q, RLC_WIDTH);

		l = RLC_FP_BITS + 1;
		bn_rec_reg(reg[0], &l, m[0], bn_bits(n) >> 1, RLC_WIDTH);
		l = RLC_FP_BITS + 1;
		bn_rec_reg(reg[1], &l, m[1], bn_bits(n) >> 1, RLC_WIDTH);

#if defined(EP_MIXED)
		fp_set_dig(u->z, 1);
		fp_set_dig(w->z, 1);
		u->coord = w->coord = BASIC;
#else
		u->coord = w->coord = EP_ADD;
#endif
		ep_set_infty(r);
		for (int i = l - 1; i >= 0; i--) {
			for (size_t j = 0; j < RLC_WIDTH - 1; j++) {
				ep_dbl(r, r);
			}

			n0 = reg[0][i];
			c0 = (n0 >> 7);
			n0 = ((n0 ^ c0) - c0) >> 1;
			n1 = reg[1][i];
			c1 = (n1 >> 7);
			n1 = ((n1 ^ c1) - c1) >> 1;

			for (size_t j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {
				fp_copy_sec(u->x, t[j]->x, j == n0);
				fp_copy_sec(w->x, t[j]->x, j == n1);
				fp_copy_sec(u->y, t[j]->y, j == n0);
				fp_copy_sec(w->y, t[j]->y, j == n1);
#if !defined(EP_fpXED)
				fp_copy_sec(u->z, t[j]->z, j == n0);
				fp_copy_sec(w->z, t[j]->z, j == n1);
#endif
			}
			ep_neg(q, u);
			fp_copy_sec(q->y, u->y, c0 == 0);
			ep_add(r, r, q);

			ep_psi(w, w);
			ep_neg(q, w);
			fp_copy_sec(w->y, q->y, (c1 != 0) ^ (s[0] != s[1]));
			ep_add(r, r, w);
		}

		/* t[0] has an unmodified copy of p. */
		ep_sub(u, r, t[0]);
		fp_copy_sec(r->x, u->x, b[0]);
		fp_copy_sec(r->y, u->y, b[0]);
		fp_copy_sec(r->z, u->z, b[0]);

		ep_psi(w, t[0]);
		ep_neg(q, w);
		fp_copy_sec(q->y, w->y, s[0] == s[1]);
		ep_sub(u, r, q);
		fp_copy_sec(r->x, u->x, b[1]);
		fp_copy_sec(r->y, u->y, b[1]);
		fp_copy_sec(r->z, u->z, b[1]);

		/* Convert r to affine coordinates. */
		ep_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(m[0]);
		bn_free(m[1]);
		bn_free(n);
		ep_free(q);
		ep_free(u);
		ep_free(w);
		for (size_t i = 0; i < 1 << (RLC_WIDTH - 2); i++) {
			ep_free(t[i]);
		}
	}
}

#endif /* EP_ENDOM */

#if defined(EP_PLAIN) || defined(EP_SUPER)

static void ep_mul_reg_imp(ep_t r, const ep_t p, const bn_t k) {
	bn_t m;
	int i, j, n;
	int8_t s, reg[1 + RLC_CEIL(RLC_FP_BITS + 1, RLC_WIDTH - 1)];
	ep_t t[1 << (RLC_WIDTH - 2)], u, v;
	size_t l;

	bn_null(m);

	RLC_TRY {
		bn_new(m);
		ep_new(u);
		ep_new(v);
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep_null(t[i]);
			ep_new(t[i]);
		}
		/* Compute the precomputation table. */
		ep_tab(t, p, RLC_WIDTH);

		ep_curve_get_ord(m);
		n = bn_bits(m);

		/* Make a copy of the scalar for processing. */
		bn_abs(m, k);
		m->dp[0] |= 1;

		/* Compute the regular w-NAF representation of k. */
		l = RLC_CEIL(n, RLC_WIDTH - 1) + 1;
		bn_rec_reg(reg, &l, m, n, RLC_WIDTH);

#if defined(EP_MIXED)
		fp_set_dig(u->z, 1);
		u->coord = BASIC;
#else
		u->coord = EP_ADD;
#endif
		ep_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			for (j = 0; j < RLC_WIDTH - 1; j++) {
				ep_dbl(r, r);
			}

			n = reg[i];
			s = (n >> 7);
			n = ((n ^ s) - s) >> 1;

			for (j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {
				fp_copy_sec(u->x, t[j]->x, j == n);
				fp_copy_sec(u->y, t[j]->y, j == n);
#if !defined(EP_MIXED)
				fp_copy_sec(u->z, t[j]->z, j == n);
#endif
			}
			ep_neg(v, u);
			fp_copy_sec(u->y, v->y, s != 0);
			ep_add(r, r, u);
		}
		/* t[0] has an unmodified copy of p. */
		ep_sub(u, r, t[0]);
		fp_copy_sec(r->x, u->x, bn_is_even(k));
		fp_copy_sec(r->y, u->y, bn_is_even(k));
		fp_copy_sec(r->z, u->z, bn_is_even(k));
		/* Convert r to affine coordinates. */
		ep_norm(r, r);
		ep_neg(u, r);
		fp_copy_sec(r->y, u->y, bn_sign(k) == RLC_NEG);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep_free(t[i]);
		}
		bn_free(m);
		ep_free(u);
		ep_free(v);
	}
}

#endif /* EP_PLAIN || EP_SUPER */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep_mul_basic(ep_t r, const ep_t p, const bn_t k) {
	ep_t t;
	int8_t u, *naf = RLC_ALLOCA(int8_t, bn_bits(k) + 1);
	size_t l;

	ep_null(t);

	if (bn_is_zero(k) || ep_is_infty(p)) {
		ep_set_infty(r);
		RLC_FREE(naf);
		return;
	}

	if (bn_bits(k) <= RLC_DIG) {
		ep_mul_dig(r, p, k->dp[0]);
		if (bn_sign(k) == RLC_NEG) {
			ep_neg(r, r);
		}
		RLC_FREE(naf);
		return;
	}

	RLC_TRY {
		ep_new(t);
		if (naf == NULL) {
			RLC_THROW(ERR_NO_BUFFER);
		}

		l = bn_bits(k) + 1;
		bn_rec_naf(naf, &l, k, 2);
		ep_copy(t, p);
		for (int i = l - 2; i >= 0; i--) {
			ep_dbl(t, t);

			u = naf[i];
			if (u > 0) {
				ep_add(t, t, p);
			} else if (u < 0) {
				ep_sub(t, t, p);
			}
		}

		ep_norm(r, t);
		if (bn_sign(k) == RLC_NEG) {
			ep_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
		RLC_FREE(naf);
	}
}

#if EP_MUL == SLIDE || !defined(STRIP)

void ep_mul_slide(ep_t r, const ep_t p, const bn_t k) {
	bn_t m, n;
	ep_t t[1 << (RLC_WIDTH - 1)], q;
	uint8_t win[RLC_FP_BITS + 1];
	size_t l;

	if (bn_is_zero(k) || ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

	ep_null(q);
	bn_null(n);
	bn_null(m);

	RLC_TRY {
		bn_new(n);
		bn_new(m);
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 1)); i ++) {
			ep_null(t[i]);
			ep_new(t[i]);
		}
		ep_new(q);

		ep_copy(t[0], p);
		ep_dbl(q, p);

#if defined(EP_MIXED)
		ep_norm(q, q);
#endif

		ep_curve_get_ord(n);
		bn_mod(m, k, n);

		/* Create table. */
		for (size_t i = 1; i < (1 << (RLC_WIDTH - 1)); i++) {
			ep_add(t[i], t[i - 1], q);
		}

#if defined(EP_MIXED)
		ep_norm_sim(t + 1, (const ep_t *)t + 1, (1 << (RLC_WIDTH - 1)) - 1);
#endif

		ep_set_infty(q);
		l = RLC_FP_BITS + 1;
		bn_rec_slw(win, &l, m, RLC_WIDTH);
		for (size_t i = 0; i < l; i++) {
			if (win[i] == 0) {
				ep_dbl(q, q);
			} else {
				for (size_t j = 0; j < util_bits_dig(win[i]); j++) {
					ep_dbl(q, q);
				}
				ep_add(q, q, t[win[i] >> 1]);
			}
		}

		ep_norm(r, q);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(m);
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 1)); i++) {
			ep_free(t[i]);
		}
		ep_free(q);
	}
}

#endif

#if EP_MUL == MONTY || !defined(STRIP)

void ep_mul_monty(ep_t r, const ep_t p, const bn_t k) {
	ep_t t[2];
	bn_t n, l, m;
	size_t bits;

	bn_null(n);
	bn_null(l);
	bn_null(m);
	ep_null(t[0]);
	ep_null(t[1]);

	if (bn_is_zero(k) || ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(l);
		bn_new(m);
		ep_new(t[0]);
		ep_new(t[1]);

		ep_curve_get_ord(n);
		bits = bn_bits(n);

		bn_mod(m, k, n);
		bn_abs(l, m);
		bn_add(l, l, n);
		bn_add(n, l, n);
		dv_swap_sec(l->dp, n->dp, RLC_MAX(l->used, n->used),
			bn_get_bit(l, bits) == 0);
		l->used = RLC_SEL(l->used, n->used, bn_get_bit(l, bits) == 0);

		ep_norm(t[0], p);
		ep_dbl(t[1], t[0]);

		/* Blind both points independently. */
		ep_blind(t[0], t[0]);
		ep_blind(t[1], t[1]);

		for (int i = bits - 1; i >= 0; i--) {
 			int j = bn_get_bit(l, i);
			dv_swap_sec(t[0]->x, t[1]->x, RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y, t[1]->y, RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z, t[1]->z, RLC_FP_DIGS, j ^ 1);
			ep_add(t[0], t[0], t[1]);
			ep_dbl(t[1], t[1]);
			dv_swap_sec(t[0]->x, t[1]->x, RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y, t[1]->y, RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z, t[1]->z, RLC_FP_DIGS, j ^ 1);
		}

		ep_norm(r, t[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(l);
		bn_free(m);
		ep_free(t[1]);
		ep_free(t[0]);
	}
}

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep_mul_lwnaf(ep_t r, const ep_t p, const bn_t k) {
	if (bn_is_zero(k) || ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		ep_mul_glv_imp(r, p, k);
		return;
	}
#endif

#if defined(EP_PLAIN) || defined(EP_SUPER)
	ep_mul_naf_imp(r, p, k);
#endif
}

#endif

/* Conditional compilation of the function below was turned off because it
 * is used by the default for protected scalar multiplication in G1. */
void ep_mul_lwreg(ep_t r, const ep_t p, const bn_t k) {
	if (bn_is_zero(k) || ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		ep_mul_reg_glv(r, p, k);
		return;
	}
#endif

#if defined(EP_PLAIN) || defined(EP_SUPER)
	ep_mul_reg_imp(r, p, k);
#endif
}

void ep_mul_gen(ep_t r, const bn_t k) {
	if (bn_is_zero(k)) {
		ep_set_infty(r);
		return;
	}

#ifdef EP_PRECO
	ep_mul_fix(r, ep_curve_get_tab(), k);
#else
	ep_t g;

	ep_null(g);

	RLC_TRY {
		ep_new(g);
		ep_curve_get_gen(g);
		ep_mul(r, g, k);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(g);
	}
#endif
}

void ep_mul_dig(ep_t r, const ep_t p, dig_t k) {
	ep_t t;
	bn_t m;
	int8_t u, naf[RLC_DIG + 1];
	size_t l;

	ep_null(t);
	bn_null(m);

	if (k == 0 || ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

	RLC_TRY {
		ep_new(t);
		bn_new(m);

		bn_set_dig(m, k);

		l = RLC_DIG + 1;
		bn_rec_naf(naf, &l, m, 2);

		ep_copy(t, p);
		for (int i = l - 2; i >= 0; i--) {
			ep_dbl(t, t);

			u = naf[i];
		if (i == l - 2) {
			printf("eita %d\n", u);
		}
			if (u > 0) {
				ep_add(t, t, p);
			} else if (u < 0) {
				ep_sub(t, t, p);
			}
		}

		ep_norm(r, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
		bn_free(m);
	}
}
