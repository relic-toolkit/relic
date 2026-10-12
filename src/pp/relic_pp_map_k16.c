/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of the line functions and pairings for curves with embedding
 * degree 16.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp_tmpl.h"
#include "relic_pp.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

TMPL_PP_MIL(16, ep4);

TMPL_PP_MIL_LIT(16, ep4);

/**
 * Compute the final lines for optimal ate pairings.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] q				- the first point of the pairing, in G_2.
 * @param[in] p				- the second point of the pairing, in G_1.
 * @param[in] a				- the loop parameter.
 */
static void pp_fin_k16_oatep(fp16_t r, ep4_t t, const ep4_t q, const ep_t p) {
	ep4_t q1, q2;
	fp16_t tmp;
	ep_t _p;

	fp16_null(tmp);
	ep4_null(q1);
	ep4_null(q2);
	ep_null(_p);

	RLC_TRY {
		ep4_new(q1);
		ep4_new(q2);
		fp16_new(tmp);
		ep_new(_p);

		TMPL_PP_MIL_P_16(_p, p)

		fp16_zero(tmp);
		ep4_frb(q1, q, 1);
		pp_add_k16(tmp, t, q1, p);
		fp16_frb(tmp, tmp, 3);
		fp16_mul_dxs(r, r, tmp);

		fp16_zero(tmp);
		pp_dbl_k16(tmp, q2, q, _p);
		fp16_mul_dxs(r, r, tmp);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp16_free(tmp);
		ep4_free(q1);
		ep4_free(q2);
		ep_free(_p);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_ADD_BASIC(16, ep4, fp4);

TMPL_PP_ADD_PROJC4(16, ep4, fp4);

TMPL_PP_ADD_LAZYR4(16, ep4, fp4, dv4);

TMPL_PP_ADD_LIT(16, ep4, fp4);

TMPL_PP_DBL_BASIC(16, ep4, fp4);

TMPL_PP_DBL_PROJC4(16, ep4, fp4);

TMPL_PP_DBL_LIT4(16, ep4, fp4);

TMPL_PP_MAP_TATEP(16, ep4);

TMPL_PP_MAP_SIM_TATEP(16, ep4);

TMPL_PP_MAP_WEILP(16, ep4);

TMPL_PP_MAP_SIM_WEILP(16, ep4);

void pp_map_oatep_k16(fp16_t r, const ep_t p, const ep4_t q) {
	ep_t _p[1];
	ep4_t t[1], _q[1];
	bn_t a;

	ep_null(_p[0]);
	ep4_null(_q[0]);
	ep4_null(t[0]);
	bn_null(a);

	RLC_TRY {
		ep_new(_p[0]);
		ep4_new(_q[0]);
		ep4_new(t[0]);
		bn_new(a);

		fp_prime_get_par(a);
		fp16_set_dig(r, 1);

		ep_norm(_p[0], p);
		ep4_norm(_q[0], q);

		if (!ep_is_infty(_p[0]) && !ep4_is_infty(_q[0])) {
			switch (ep_curve_is_pairf()) {
				case EP_FM16:
				case EP_AFG16:
					/* r = f_{a,Q}(P). */
					pp_mil_k16(r, t, _q, _p, 1, a);
					pp_exp_k16(r, r);
					break;
				case EP_K16:
					/* r = f_{a,Q}(P). */
					pp_mil_k16(r, t, _q, _p, 1, a);
					fp16_frb(r, r, 3);
					pp_fin_k16_oatep(r, t[0], _q[0], _p[0]);
					pp_exp_k16(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep4_free(_q[0]);
		ep4_free(t[0]);
		bn_free(a);
	}
}

void pp_map_sim_oatep_k16(fp16_t r, const ep_t *p, const ep4_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep4_t *t = RLC_ALLOCA(ep4_t, m), *_q = RLC_ALLOCA(ep4_t, m);
	bn_t a;
	int i, j;

	if (_p == NULL || _q == NULL || t == NULL) {
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	bn_null(a);
	for (i = 0; i < m; i++) {
		ep_null(_p[i]);
		ep4_null(_q[i]);
		ep4_null(t[i]);
	}

	RLC_TRY {
		bn_new(a);
		for (i = 0; i < m; i++) {
			ep_new(_p[i]);
			ep4_new(_q[i]);
			ep4_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep4_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep4_norm(_q[j++], q[i]);
			}
		}

		fp_prime_get_par(a);
		fp16_set_dig(r, 1);

		if (j > 0) {
			switch (ep_curve_is_pairf()) {
				case EP_FM16:
				case EP_AFG16:
					/* r = f_{a,Q}(P). */
					pp_mil_k16(r, t, _q, _p, j, a);
					pp_exp_k16(r, r);
					break;
				case EP_K16:
					/* r = f_{a,Q}(P). */
					pp_mil_k16(r, t, _q, _p, j, a);
					fp16_frb(r, r, 3);
					for (i = 0; i < j; i++) {
						pp_fin_k16_oatep(r, t[i], _q[i], _p[i]);
					}
					pp_exp_k16(r, r);
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
			ep4_free(_q[i]);
			ep4_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}
