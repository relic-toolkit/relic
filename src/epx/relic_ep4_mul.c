/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Implementation of point multiplication on prime elliptic curves over a
 * quartic extension field.
 *
 * @ingroup epx
 */
#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if defined(EP_ENDOM)

#if EP_MUL == LWNAF || !defined(STRIP)

static void ep4_mul_gls_imp(ep4_t r, const ep4_t p, const bn_t k) {
	size_t l, _l[8], w = RLC_WIDTH;
	bn_t n, _k[8], u;
	int8_t naf[8][RLC_FP_BITS + 1];
	ep4_t q, t[8][1 << (RLC_WIDTH - 2)];

	bn_null(n);
	bn_null(u);
	ep4_null(q);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		ep4_new(q);
		for (size_t i = 0; i < 8; i++) {
			bn_null(_k[i]);
			bn_new(_k[i]);
			for (size_t j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {
				ep4_null(t[i][j]);
				ep4_new(t[i][j]);
			}	
		}

		ep4_curve_get_ord(n);
		fp_prime_get_par(u);
		bn_mod(_k[0], k, n);
		bn_rec_frb(_k, 8, _k[0], u, n, ep_curve_is_pairf() == EP_BN);

		l = 0;
		for (size_t i = 0; i < 8; i++) {
			l = RLC_MAX(l, bn_bits(_k[i]));
		}
		if (l < bn_bits(u) / 2) {
			w = 2;
		}

		l = 0;
		for (size_t i = 0; i < 8; i++) {
			_l[i] = RLC_FP_BITS + 1;
			bn_rec_naf(naf[i], &_l[i], _k[i], w);
			l = RLC_MAX(l, _l[i]);
		}
		ep4_norm(q, p);
		if (bn_sign(_k[0]) == RLC_NEG) {
			ep4_neg(q, q);
		}
		ep4_tab(t[0], q, w);

		if (ep_curve_is_pairf() == EP_K16 || ep_curve_is_pairf() == EP_AFG16) {
			/* Minimize use of endomorphism when it's expensive. */
			for (size_t i = 1; i < 8; i++) {
				ep4_psi(q, t[i - 1][0]);
				if (bn_sign(_k[i]) == RLC_NEG) {
					ep4_neg(q, q);
				}
				ep4_tab(t[i], q, w);
			}
		} else {
			for (size_t i = 1; i < 8; i++) {
				for (size_t j = 0; j < (1 << (w - 2)); j++) {
					ep4_psi(t[i][j], t[i - 1][j]);
					if (bn_sign(_k[i]) != bn_sign(_k[i - 1])) {
						ep4_neg(t[i][j], t[i][j]);
					}
				}
			}
		}

		ep4_set_infty(r);
		for (int j = l - 1; j >= 0; j--) {
			ep4_dbl(r, r);

			for (size_t i = 0; i < 8; i++) {
				if (naf[i][j] > 0) {
					ep4_add(r, r, t[i][naf[i][j] / 2]);
				}
				if (naf[i][j] < 0) {
					ep4_sub(r, r, t[i][-naf[i][j] / 2]);
				}
			}
		}

		/* Convert r to affine coordinates. */
		ep4_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		ep4_free(q);
		for (size_t i = 0; i < 8; i++) {
			bn_free(_k[i]);
			for (size_t j = 0; j < (1 << (RLC_WIDTH - 2)); j++) {
				ep4_free(t[i][j]);
			}	
		}
	}
}

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

static void ep4_mul_reg_gls(ep4_t r, const ep4_t p, const bn_t k) {
	size_t l, c = 2, m = 8;
	bn_t n, _k[8], u;
	int8_t even[2], col, sac[2][4 * (RLC_FP_BITS + 1)];
	ep4_t q[8], t[2][1 << 3];

	bn_null(n);
	bn_null(u);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (int i = 0; i < 8; i++) {
			bn_null(_k[i]);
			ep4_null(q[i]);
			bn_new(_k[i]);
			ep4_new(q[i]);
		}
		for (size_t i = 0; i < c; i++) {
			for (int j = 0; j < (1 << 3); j++) {
				ep4_null(t[i][j]);
				ep4_new(t[i][j]);
			}
		}

		ep4_curve_get_ord(n);
		fp_prime_get_par(u);
		bn_mod(_k[0], k, n);
		bn_rec_frb(_k, 8, _k[0], u, n, ep_curve_is_pairf() == EP_BN);

		ep4_norm(q[0], p);
		for (size_t i = 1; i < 8; i++) {
			ep4_psi(q[i], q[i - 1]);
		}
		for (size_t i = 0; i < 8; i++) {
			ep4_neg(r, q[i]);
			fp4_copy_sec(q[i]->y, r->y, bn_sign(_k[i]) == RLC_NEG);
			bn_abs(_k[i], _k[i]);
		}
		for (size_t i = 0; i < c; i++) {
			even[i] = bn_is_even(_k[i * m / c]);
			bn_add_dig(_k[i * m / c], _k[i * m / c], even[i]);
		}
		
		for (size_t i = 0; i < c; i++) {
			ep4_copy(t[i][0], q[i * m / c]);
			for (size_t j = 1; j < (1 << 3); j++) {
				l = util_bits_dig(j);
				ep4_add(t[i][j], t[i][j ^ (1 << (l - 1))], q[l + i * m / c]);
			}
			l = RLC_FP_BITS + 1;
			bn_rec_sac(sac[i], &l, _k + i * m / c, u, c, m / c, bn_bits(n), 0);
		}

#if defined(EP_MIXED)
		for (size_t i = 0; i < c; i++) {
			/* The endomorphism may return points in projective coordinates. */
			ep4_norm_sim(t[i], (const ep4_t *)t[i], 1 << 3);
		}
		fp4_set_dig(r->z, 1);
		fp4_set_dig(q[1]->z, 1);
		r->coord = q[1]->coord = BASIC;
#else
		r->coord = q[1]->coord = EP_ADD;
#endif

		ep4_set_infty(r);
		for (size_t i = 0; i < c; i++) {
			col = 0;
			for (int j = 3; j > 0; j--) {
				col <<= 1;
				col += sac[i][j * l + l - 1];
			}
			for (size_t m = 0; m < (1 << 3); m++) {
				fp4_copy_sec(q[1]->x, t[i][m]->x, m == col);
				fp4_copy_sec(q[1]->y, t[i][m]->y, m == col);
#if !defined(EP_MIXED)
				fp4_copy_sec(q[1]->z, t[i][m]->z, m == col);
#endif
			}
			ep4_neg(q[2], q[1]);
			fp4_copy_sec(q[1]->y, q[2]->y, sac[i][l - 1]);
			ep4_add(r, r, q[1]);
		}

		for (int j = l - 2; j >= 0; j--) {
			ep4_dbl(r, r);

			for (size_t i = 0; i < c; i++) {
				col = 0;
				for (int k = 3; k > 0; k--) {
					col <<= 1;
					col += sac[i][k * l + j];
				}
			
				for (size_t m = 0; m < (1 << 3); m++) {
					fp4_copy_sec(q[1]->x, t[i][m]->x, m == col);
					fp4_copy_sec(q[1]->y, t[i][m]->y, m == col);
#if !defined(EP_MIXED)
					fp4_copy_sec(q[1]->z, t[i][m]->z, m == col);
#endif
				}
				ep4_neg(q[2], q[1]);
				fp4_copy_sec(q[1]->y, q[2]->y, sac[i][j]);
				ep4_add(r, r, q[1]);
			}
		}

		for (size_t i = 0; i < c; i++) {
			ep4_sub(q[1], r, q[i * m / c]);
			fp4_copy_sec(r->x, q[1]->x, even[i]);
			fp4_copy_sec(r->y, q[1]->y, even[i]);
			fp4_copy_sec(r->z, q[1]->z, even[i]);
		}

		/* Convert r to affine coordinates. */
		ep4_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		for (int i = 0; i < 8; i++) {
			bn_free(_k[i]);
			ep4_free(q[i]);
		}
		for (size_t i = 0; i < c; i++) {
			for (int j = 0; j < (1 << 3); j++) {
				ep4_free(t[i][j]);
			}
		}
	}
}

#endif /* EP_MUL == LWREG */
#endif /* EP_ENDOM */

#if defined(EP_PLAIN) || defined(EP_SUPER)

#if EP_MUL == LWNAF || !defined(STRIP)

static void ep4_mul_naf_imp(ep4_t r, const ep4_t p, const bn_t k) {
	int i, n;
	int8_t naf[RLC_FP_BITS + 1];
	ep4_t t[1 << (RLC_WIDTH - 2)];
	size_t l;

	RLC_TRY {
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep4_null(t[i]);
			ep4_new(t[i]);
		}
		/* Compute the precomputation table. */
		ep4_tab(t, p, RLC_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = sizeof(naf);
		bn_rec_naf(naf, &l, k, RLC_WIDTH);

		ep4_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
			ep4_dbl(r, r);

			n = naf[i];
			if (n > 0) {
				ep4_add(r, r, t[n / 2]);
			}
			if (n < 0) {
				ep4_sub(r, r, t[-n / 2]);
			}
		}
		/* Convert r to affine coordinates. */
		ep4_norm(r, r);
		if (bn_sign(k) == RLC_NEG) {
			ep4_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep4_free(t[i]);
		}
	}
}

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep4, fp4);

#endif /* EP_MUL == LWREG */
#endif /* EP_PLAIN || EP_SUPER */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep4);

#if EP_MUL == SLIDE || !defined(STRIP)

void ep4_mul_slide(ep4_t r, const ep4_t p, const bn_t k) {
	ep4_t t[1 << (RLC_WIDTH - 1)], q;
	uint8_t win[RLC_FP_BITS + 1];
	size_t l;

	ep4_null(q);

	if (bn_is_zero(k) || ep4_is_infty(p)) {
		ep4_set_infty(r);
		return;
	}

	RLC_TRY {
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 1)); i ++) {
			ep4_null(t[i]);
			ep4_new(t[i]);
		}

		ep4_new(q);

		ep4_copy(t[0], p);
		ep4_dbl(q, p);

#if defined(EP_MIXED)
		ep4_norm(q, q);
#endif

		/* Create table. */
		for (size_t i = 1; i < (1 << (RLC_WIDTH - 1)); i++) {
			ep4_add(t[i], t[i - 1], q);
		}

#if defined(EP_MIXED)
		ep4_norm_sim(t + 1, t + 1, (1 << (RLC_WIDTH - 1)) - 1);
#endif

		ep4_set_infty(q);
		l = RLC_FP_BITS + 1;
		bn_rec_slw(win, &l, k, RLC_WIDTH);
		for (size_t i = 0; i < l; i++) {
			if (win[i] == 0) {
				ep4_dbl(q, q);
			} else {
				for (size_t j = 0; j < util_bits_dig(win[i]); j++) {
					ep4_dbl(q, q);
				}
				ep4_add(q, q, t[win[i] >> 1]);
			}
		}

		ep4_norm(r, q);
		if (bn_sign(k) == RLC_NEG) {
			ep4_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (size_t i = 0; i < (1 << (RLC_WIDTH - 1)); i++) {
			ep4_free(t[i]);
		}
		ep4_free(q);
	}
}

#endif

#if EP_MUL == MONTY || !defined(STRIP)

void ep4_mul_monty(ep4_t r, const ep4_t p, const bn_t k) {
	ep4_t t[2];
	bn_t n, l, _k;
	size_t bits;

	bn_null(n);
	bn_null(l);
	bn_null(_k);
	ep4_null(t[0]);
	ep4_null(t[1]);

	if (bn_is_zero(k) || ep4_is_infty(p)) {
		ep4_set_infty(r);
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(l);
		bn_new(_k);
		ep4_new(t[0]);
		ep4_new(t[1]);

		ep4_curve_get_ord(n);
		bits = bn_bits(n);

		bn_mod(_k, k, n);
		bn_abs(l, _k);
		bn_add(l, l, n);
		bn_add(n, l, n);
		dv_swap_sec(l->dp, n->dp, RLC_MAX(l->used, n->used),
			bn_get_bit(l, bits) == 0);
		l->used = RLC_SEL(l->used, n->used, bn_get_bit(l, bits) == 0);

		ep4_norm(t[0], p);
		ep4_dbl(t[1], t[0]);

		/* Blind both points independently. */
		ep4_blind(t[0], t[0]);
		ep4_blind(t[1], t[1]);

		for (int i = bits - 1; i >= 0; i--) {
			int j = bn_get_bit(l, i);
			dv_swap_sec(t[0]->x[0][0], t[1]->x[0][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->x[0][1], t[1]->x[0][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->x[1][0], t[1]->x[1][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->x[1][1], t[1]->x[1][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[0][0], t[1]->y[0][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[0][1], t[1]->y[0][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[1][0], t[1]->y[1][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[1][1], t[1]->y[1][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[0][0], t[1]->z[0][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[0][1], t[1]->z[0][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[1][0], t[1]->z[1][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[1][1], t[1]->z[1][1], RLC_FP_DIGS, j ^ 1);
			ep4_add(t[0], t[0], t[1]);
			ep4_dbl(t[1], t[1]);
			dv_swap_sec(t[0]->x[0][0], t[1]->x[0][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->x[0][1], t[1]->x[0][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->x[1][0], t[1]->x[1][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->x[1][1], t[1]->x[1][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[0][0], t[1]->y[0][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[0][1], t[1]->y[0][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[1][0], t[1]->y[1][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[1][1], t[1]->y[1][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[0][0], t[1]->z[0][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[0][1], t[1]->z[0][1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[1][0], t[1]->z[1][0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[1][1], t[1]->z[1][1], RLC_FP_DIGS, j ^ 1);
		}

		ep4_norm(r, t[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(l);
		bn_free(_k);
		ep4_free(t[1]);
		ep4_free(t[0]);
	}
}

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep4_mul_lwnaf(ep4_t r, const ep4_t p, const bn_t k) {
	if (bn_is_zero(k) || ep4_is_infty(p)) {
		ep4_set_infty(r);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		ep4_mul_gls_imp(r, p, k);
		return;
	}
#endif

#if defined(EP_PLAIN) || defined(EP_SUPER)
	ep4_mul_naf_imp(r, p, k);
#endif
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep4_mul_lwreg(ep4_t r, const ep4_t p, const bn_t k) {
	if (bn_is_zero(k) || ep4_is_infty(p)) {
		ep4_set_infty(r);
		return;
	}

#if defined(EP_ENDOM)
	if (ep_curve_is_endom()) {
		ep4_mul_reg_gls(r, p, k);
		return;
	}
#endif

#if defined(EP_PLAIN) || defined(EP_SUPER)
	ep4_mul_reg_imp(r, p, k);
#endif
}

#endif

TMPL_EP_MUL_GEN(ep4);

TMPL_EP_MUL_DIG(ep4);
