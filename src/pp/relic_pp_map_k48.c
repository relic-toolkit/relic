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
 * Implementation of pairing computation for curves with embedding degree 48.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                         */
/*============================================================================*/

/**
 * Compute the Miller loop for pairings of type G_2 x G_1 over the bits of a
 * given parameter represented in sparse form.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] q				- the vector of first arguments in affine coordinates.
 * @param[in] p				- the vector of second arguments in affine coordinates.
 * @param[in] n 			- the number of pairings to evaluate.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_k48(fp48_t r, ep8_t *t, ep8_t *q, ep_t *p, int m, bn_t a) {
	fp48_t l;
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep8_t *_q = RLC_ALLOCA(ep8_t, m);
	size_t len = bn_bits(a) + 1;
	int i, j;
	int8_t s[RLC_FP_BITS + 1];

	if (m == 0) {
		return;
	}

	fp48_null(l);

	RLC_TRY {
		fp48_new(l);
		if (_p == NULL || _q == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		for (j = 0; j < m; j++) {
			ep_null(_p[j]);
			ep8_null(_q[j]);
			ep_new(_p[j]);
			ep8_new(_q[j]);
			ep8_copy(t[j], q[j]);
			ep8_neg(_q[j], q[j]);
#if EP_ADD == BASIC
			ep_neg(_p[j], p[j]);
#else
			fp_add(_p[j]->x, p[j]->x, p[j]->x);
			fp_add(_p[j]->x, _p[j]->x, p[j]->x);
			fp_neg(_p[j]->y, p[j]->y);
#endif
		}

		fp48_zero(l);
		bn_rec_naf(s, &len, a, 2);
		pp_dbl_k48(r, t[0], t[0], _p[0]);
		for (j = 1; j < m; j++) {
			pp_dbl_k48(l, t[j], t[j], _p[j]);
			fp48_mul_dxs(r, r, l);
		}
		if (s[len - 2] > 0) {
			for (j = 0; j < m; j++) {
				pp_add_k48(l, t[j], q[j], p[j]);
				fp48_mul_dxs(r, r, l);
			}
		}
		if (s[len - 2] < 0) {
			for (j = 0; j < m; j++) {
				pp_add_k48(l, t[j], _q[j], p[j]);
				fp48_mul_dxs(r, r, l);
			}
		}

		for (i = len - 3; i >= 0; i--) {
			fp48_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_k48(l, t[j], t[j], _p[j]);
				fp48_mul_dxs(r, r, l);
				if (s[i] > 0) {
					pp_add_k48(l, t[j], q[j], p[j]);
					fp48_mul_dxs(r, r, l);
				}
				if (s[i] < 0) {
					pp_add_k48(l, t[j], _q[j], p[j]);
					fp48_mul_dxs(r, r, l);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp48_free(l);
		for (j = 0; j < m; j++) {
			ep_free(_p[j]);
			ep8_free(_q[j]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if PP_MAP == OATEP || !defined(STRIP)

void pp_map_k48(fp48_t r, const ep_t p, const ep8_t q) {
	ep_t _p[1];
	ep8_t t[1], _q[1];
	bn_t a;

	ep_null(_p[0]);
	ep8_null(_q[0]);
	ep8_null(t[0]);
	bn_null(a);

	RLC_TRY {
		ep_new(_p[0]);
		ep8_new(_q[0]);
		ep8_new(t[0]);
		bn_new(a);

		fp_prime_get_par(a);
		fp48_set_dig(r, 1);

		ep_norm(_p[0], p);
		ep8_norm(_q[0], q);

		if (!ep_is_infty(_p[0]) && !ep8_is_infty(_q[0])) {
			switch (ep_curve_is_pairf()) {
				case EP_B48:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k48(r, t, _q, _p, 1, a);
					if (bn_sign(a) == RLC_NEG) {
						fp48_inv_cyc(r, r);
					}
					pp_exp_k48(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep8_free(_q[0]);
		ep8_free(t[0]);
		bn_free(a);
	}
}

void pp_map_sim_k48(fp48_t r, const ep_t *p, const ep8_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep8_t *t = RLC_ALLOCA(ep8_t, m), *_q = RLC_ALLOCA(ep8_t, m);
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
			ep8_null(_q[i]);
			ep8_null(t[i]);
			ep_new(_p[i]);
			ep8_new(_q[i]);
			ep8_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep8_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep8_norm(_q[j++], q[i]);
			}
		}

		fp_prime_get_par(a);
		fp48_set_dig(r, 1);

		if (j > 0) {
			switch (ep_curve_is_pairf()) {
				case EP_B48:
					/* r = f_{|a|,Q}(P). */
					pp_mil_k48(r, t, _q, _p, j, a);
					if (bn_sign(a) == RLC_NEG) {
						fp48_inv_cyc(r, r);
					}
					pp_exp_k48(r, r);
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
			ep8_free(_q[i]);
			ep8_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}

#endif
