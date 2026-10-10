/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
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
 * Implementation of pairing computation for curves with embedding degree 54.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Compute the Miller loop for pairings of type G_2 x G_1 over the bits of a
 * given parameter represented in sparse form.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting points.
 * @param[in] q				- the vector of affine points in G_2.
 * @param[in] p				- the vector of affine points in G_1.
 * @param[in] m				- the number of pairings to evaluate.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_k54(fp54_t r, ep9_t *t, const ep9_t *q, const ep_t *p,
		int m, const bn_t a) {
	fp54_t l;
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep9_t s, u;
	size_t len = bn_bits(a) + 1;
	int i, j;
	int8_t naf[RLC_FP_BITS + 1];

	if (m == 0) {
		return;
	}

	fp54_null(l);
	ep9_null(s);
	ep9_null(u);

	RLC_TRY {
		fp54_new(l);
		ep9_new(s);
		ep9_new(u);
		if (_p == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (j = 0; j < m; j++) {
			ep_null(_p[j]);
			ep_new(_p[j]);
			ep9_copy(t[j], q[j]);
#if EP_ADD == BASIC
			ep_neg(_p[j], p[j]);
#else
			fp_add(_p[j]->x, p[j]->x, p[j]->x);
			fp_add(_p[j]->x, _p[j]->x, p[j]->x);
			fp_neg(_p[j]->y, p[j]->y);
#endif
		}

		fp54_zero(l);
		bn_rec_naf(naf, &len, a, 2);
		for (i = len - 2; i >= 0; i--) {
			fp54_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_k54(l, t[j], t[j], _p[j]);
				fp54_mul_dxs(r, r, l);
				if (naf[i] > 0) {
					pp_add_k54(l, t[j], q[j], p[j]);
					fp54_mul_dxs(r, r, l);
				}
				if (naf[i] < 0) {
					ep9_neg(u, q[j]);
					pp_add_k54(l, t[j], u, p[j]);
					fp54_mul_dxs(r, r, l);
				}
			}
		}
		/* Compute f^3. */
		fp54_sqr(l, r);
		fp54_mul(r, r, l);

		for (j = 0; j < m; j++) {
			/* Multiply by the lines through T and 2T. */
			fp54_zero(l);
			pp_dbl_k54(l, s, t[j], _p[j]);
			fp54_mul_dxs(r, r, l);
			pp_norm_k54(s, s);
			pp_add_k54(l, t[j], s, p[j]);
			fp54_mul_dxs(r, r, l);

			/* Multiply by the line through Frob^10(Q) and Frob(Q). */
			ep9_frb(u, q[j], 1);
			ep9_frb(s, q[j], 10);
			pp_add_k54(l, s, u, p[j]);
			fp54_mul_dxs(r, r, l);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp54_free(l);
		ep9_free(s);
		ep9_free(u);
		for (j = 0; j < m; j++) {
			ep_free(_p[j]);
		}
		RLC_FREE(_p);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_map_k54(fp54_t r, const ep_t p, const ep9_t q) {
	ep_t _p[1];
	ep9_t t[1], _q[1];
	bn_t a;

	ep_null(_p[0]);
	ep9_null(_q[0]);
	ep9_null(t[0]);
	bn_null(a);

	RLC_TRY {
		ep_new(_p[0]);
		ep9_new(_q[0]);
		ep9_new(t[0]);
		bn_new(a);

		fp_prime_get_par(a);
		fp54_set_dig(r, 1);

		ep_norm(_p[0], p);
		ep9_norm(_q[0], q);

		if (!ep_is_infty(_p[0]) && !ep9_is_infty(_q[0])) {
			switch (ep_curve_is_pairf()) {
				case EP_SG54:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k54(r, t, (const ep9_t *)_q, (const ep_t *)_p, 1, a);
					if (bn_sign(a) == RLC_NEG) {
						fp54_inv_cyc(r, r);
					}
					pp_exp_k54(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep9_free(_q[0]);
		ep9_free(t[0]);
		bn_free(a);
	}
}

void pp_map_sim_k54(fp54_t r, const ep_t *p, const ep9_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep9_t *t = RLC_ALLOCA(ep9_t, m), *_q = RLC_ALLOCA(ep9_t, m);
	bn_t a;
	int i, j;

	RLC_TRY {
		bn_null(a);
		bn_new(a);
		if (_p == NULL || _q == NULL || t == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (i = 0; i < m; i++) {
			ep_null(_p[i]);
			ep9_null(_q[i]);
			ep9_null(t[i]);
			ep_new(_p[i]);
			ep9_new(_q[i]);
			ep9_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep9_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep9_norm(_q[j++], q[i]);
			}
		}

		fp_prime_get_par(a);
		fp54_set_dig(r, 1);

		if (j > 0) {
			switch (ep_curve_is_pairf()) {
				case EP_SG54:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k54(r, t, (const ep9_t *)_q, (const ep_t *)_p, j, a);
					if (bn_sign(a) == RLC_NEG) {
						fp54_inv_cyc(r, r);
					}
					pp_exp_k54(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(a);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep9_free(_q[i]);
			ep9_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}
