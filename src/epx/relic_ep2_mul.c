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
 * Implementation of point multiplication on prime elliptic curves over a
 * quadratic extension field.
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

TMPL_EP_MUL_GLS_IMP(ep2, 4);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_GLS(ep2, fp2, 4, 1);

#endif /* EP_MUL == LWREG */

#endif /* EP_ENDOM */

#if defined(EP_PLAIN) || defined(EP_SUPER)

#if EP_MUL == LWNAF || !defined(STRIP)

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

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep2, fp2);

#endif /* EP_MUL == LWREG */
#endif /* EP_PLAIN || EP_SUPER */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep2);

#if EP_MUL == SLIDE || !defined(STRIP)

TMPL_EP_MUL_SLIDE(ep2);

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
		dv_swap_sec(l->dp, n->dp, RLC_MAX(l->used, n->used),
			bn_get_bit(l, bits) == 0);
		l->used = RLC_SEL(l->used, n->used, bn_get_bit(l, bits) == 0);

		ep2_norm(t[0], p);
		ep2_dbl(t[1], t[0]);

		/* Blind both points independently. */
		ep2_blind(t[0], t[0]);
		ep2_blind(t[1], t[1]);

		for (int i = bits - 1; i >= 0; i--) {
			int j = bn_get_bit(l, i);
			dv_swap_sec(t[0]->x[0], t[1]->x[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->x[1], t[1]->x[1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[0], t[1]->y[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[1], t[1]->y[1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[0], t[1]->z[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[1], t[1]->z[1], RLC_FP_DIGS, j ^ 1);
			ep2_add(t[0], t[0], t[1]);
			ep2_dbl(t[1], t[1]);
			dv_swap_sec(t[0]->x[0], t[1]->x[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->x[1], t[1]->x[1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[0], t[1]->y[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->y[1], t[1]->y[1], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[0], t[1]->z[0], RLC_FP_DIGS, j ^ 1);
			dv_swap_sec(t[0]->z[1], t[1]->z[1], RLC_FP_DIGS, j ^ 1);
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

TMPL_EP_MUL_GEN(ep2);

TMPL_EP_MUL_DIG(ep2);
