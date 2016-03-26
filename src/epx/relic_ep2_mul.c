/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2015 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
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

static void ep2_mul_naf_imp(ep2_t r, ep2_t p, const bn_t k) {
	int l, i, n;
	int8_t naf[FP_BITS + 1];
	ep2_t t[1 << (EP_WIDTH - 2)];

	TRY {
		/* Prepare the precomputation table. */
		for (i = 0; i < (1 << (EP_WIDTH - 2)); i++) {
			ep2_null(t[i]);
			ep2_new(t[i]);
		}
		/* Compute the precomputation table. */
		ep2_tab(t, p, EP_WIDTH);

		/* Compute the w-NAF representation of k. */
		l = sizeof(naf);
		bn_rec_naf(naf, &l, k, EP_WIDTH);

		ep2_set_infty(r);
		for (i = l - 1; i >= 0; i--) {
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
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		/* Free the precomputation table. */
		for (i = 0; i < (1 << (EP_WIDTH - 2)); i++) {
			ep2_free(t[i]);
		}
	}
}

#endif /* EP_MUL == LWNAF */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_MUL == BASIC || !defined(STRIP)

void ep2_mul_basic(ep2_t r, ep2_t p, const bn_t k) {
	int i, l;
	ep2_t t;

	ep2_null(t);
	TRY {
		ep2_new(t);
		l = bn_bits(k);

		if (bn_get_bit(k, l - 1)) {
			ep2_copy(t, p);
		} else {
			ep2_set_infty(t);
		}

		for (i = l - 2; i >= 0; i--) {
			ep2_dbl(t, t);
			if (bn_get_bit(k, i)) {
				ep2_add(t, t, p);
			}
		}

		ep2_copy(r, t);
		ep2_norm(r, r);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep2_free(t);
	}
}

#endif

#if EP_MUL == SLIDE || !defined(STRIP)

void ep2_mul_slide(ep2_t r, ep2_t p, const bn_t k) {
	ep2_t t[1 << (EP_WIDTH - 1)], q;
	int i, j, l;
	uint8_t win[FP_BITS + 1];

	ep2_null(q);

	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	TRY {
		for (i = 0; i < (1 << (EP_WIDTH - 1)); i ++) {
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
		for (i = 1; i < (1 << (EP_WIDTH - 1)); i++) {
			ep2_add(t[i], t[i - 1], q);
		}

#if defined(EP_MIXED)
		ep2_norm_sim(t + 1, (const ep2_t *)t + 1, (1 << (EP_WIDTH - 1)) - 1);
#endif

		ep2_set_infty(q);
		l = FP_BITS + 1;
		bn_rec_slw(win, &l, k, EP_WIDTH);
		for (i = 0; i < l; i++) {
			if (win[i] == 0) {
				ep2_dbl(q, q);
			} else {
				for (j = 0; j < util_bits_dig(win[i]); j++) {
					ep2_dbl(q, q);
				}
				ep2_add(q, q, t[win[i] >> 1]);
			}
		}

		ep2_norm(r, q);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		for (i = 0; i < (1 << (EP_WIDTH - 1)); i++) {
			ep2_free(t[i]);
		}
		ep2_free(q);
	}
}

#endif

#if EP_MUL == MONTY || !defined(STRIP)

void ep2_mul_monty(ep2_t r, ep2_t p, const bn_t k) {
	ep2_t t[2];

	ep2_null(t[0]);
	ep2_null(t[1]);

	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	TRY {
		ep2_new(t[0]);
		ep2_new(t[1]);

		ep2_set_infty(t[0]);
		ep2_copy(t[1], p);

		for (int i = bn_bits(k) - 1; i >= 0; i--) {
			int j = bn_get_bit(k, i);
			dv_swap_cond(t[0]->x[0], t[1]->x[0], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->x[1], t[1]->x[1], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y[0], t[1]->y[0], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y[1], t[1]->y[1], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z[0], t[1]->z[0], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z[1], t[1]->z[1], FP_DIGS, j ^ 1);
			ep2_add(t[0], t[0], t[1]);
			ep2_dbl(t[1], t[1]);
			dv_swap_cond(t[0]->x[0], t[1]->x[0], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->x[1], t[1]->x[1], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y[0], t[1]->y[0], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->y[1], t[1]->y[1], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z[0], t[1]->z[0], FP_DIGS, j ^ 1);
			dv_swap_cond(t[0]->z[1], t[1]->z[1], FP_DIGS, j ^ 1);
		}

		ep2_norm(r, t[0]);

	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep2_free(t[1]);
		ep2_free(t[0]);
	}
}

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep2_mul_lwnaf(ep2_t r, ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

/*#if defined(ep2_ENDOM)
	if (ep2_curve_is_endom()) {
		ep2_mul_glv_imp(r, p, k);
		return;
	}
#endif*/

//#if defined(ep2_PLAIN) || defined(ep2_SUPER)
	ep2_mul_naf_imp(r, p, k);
//#endif
}

#endif

void ep2_mul_gen(ep2_t r, bn_t k) {
#ifdef EP_PRECO
	ep2_mul_fix(r, ep2_curve_get_tab(), k);
#else
	ep2_t g;

	ep2_null(g);

	TRY {
		ep2_new(g);
		ep2_curve_get_gen(g);
		ep2_mul(r, g, k);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep2_free(g);
	}
#endif
}

void ep2_mul_dig(ep2_t r, ep2_t p, dig_t k) {
	int i, l;
	ep2_t t;

	ep2_null(t);

	if (k == 0) {
		ep2_set_infty(r);
		return;
	}

	TRY {
		ep2_new(t);

		l = util_bits_dig(k);

		ep2_copy(t, p);

		for (i = l - 2; i >= 0; i--) {
			ep2_dbl(t, t);
			if (k & ((dig_t)1 << i)) {
				ep2_add(t, t, p);
			}
		}

		ep2_norm(r, t);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep2_free(t);
	}
}
