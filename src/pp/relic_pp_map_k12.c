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
 * Implementation of pairing computation for curves with embedding degree 12.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp_tmpl.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

TMPL_PP_MIL(12, ep2);

TMPL_PP_MIL_LIT(12, ep2);

/**
 * Compute the final lines for optimal ate pairings.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] q				- the first point of the pairing, in G_2.
 * @param[in] p				- the second point of the pairing, in G_1.
 */
static void pp_fin_k12_oatep(fp12_t r, ep2_t t, const ep2_t q, const ep_t p) {
	ep2_t q1, q2;
	fp12_t tmp;

	fp12_null(tmp);
	ep2_null(q1);
	ep2_null(q2);

	RLC_TRY {
		ep2_new(q1);
		ep2_new(q2);
		fp12_new(tmp);
		fp12_zero(tmp);

		fp2_set_dig(q1->z, 1);
		fp2_set_dig(q2->z, 1);

		ep2_frb(q1, q, 1);
		ep2_frb(q2, q, 2);
		ep2_neg(q2, q2);

		pp_add_k12(tmp, t, q1, p);
		fp12_mul_dxs(r, r, tmp);
		pp_add_k12(tmp, t, q2, p);
		fp12_mul_dxs(r, r, tmp);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp12_free(tmp);
		ep2_free(q1);
		ep2_free(q2);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_MAP_TATEP(12, ep2);

TMPL_PP_MAP_SIM_TATEP(12, ep2);

TMPL_PP_MAP_WEILP(12, ep2);

TMPL_PP_MAP_SIM_WEILP(12, ep2);

void pp_map_oatep_k12(fp12_t r, const ep_t p, const ep2_t q) {
	ep_t _p[1];
	ep2_t t[1], _q[1];
	bn_t a;

	ep_null(_p[0]);
	ep2_null(_q[0]);
	ep2_null(t[0]);
	bn_null(a);

	RLC_TRY {
		ep_new(_p[0]);
		ep2_new(_q[0]);
		ep2_new(t[0]);
		bn_new(a);

		fp_prime_get_par(a);
		fp12_set_dig(r, 1);

		ep_norm(_p[0], p);
		ep2_norm(_q[0], q);

		if (!ep_is_infty(_p[0]) && !ep2_is_infty(_q[0])) {
			switch (ep_curve_is_pairf()) {
				case EP_BN:
					bn_mul_dig(a, a, 6);
					bn_add_dig(a, a, 2);
					/* r = f_{a,Q}(P). */
					pp_mil_k12(r, t, _q, _p, 1, a);
					pp_fin_k12_oatep(r, t[0], _q[0], _p[0]);
					pp_exp_k12(r, r);
					break;
				case EP_B12:
					/* r = f_{a,Q}(P). */
					pp_mil_k12(r, t, _q, _p, 1, a);
					pp_exp_k12(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep2_free(_q[0]);
		ep2_free(t[0]);
		bn_free(a);
	}
}

void pp_map_sim_oatep_k12(fp12_t r, const ep_t *p, const ep2_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep2_t *t = RLC_ALLOCA(ep2_t, m), *_q = RLC_ALLOCA(ep2_t, m);
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
		ep2_null(_q[i]);
		ep2_null(t[i]);
	}

	RLC_TRY {
		bn_new(a);
		for (i = 0; i < m; i++) {
			ep_new(_p[i]);
			ep2_new(_q[i]);
			ep2_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep2_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep2_norm(_q[j++], q[i]);
			}
		}

		fp_prime_get_par(a);
		fp12_set_dig(r, 1);

		if (j > 0) {
			switch (ep_curve_is_pairf()) {
				case EP_BN:
					bn_mul_dig(a, a, 6);
					bn_add_dig(a, a, 2);
					/* r = f_{a,Q}(P). */
					pp_mil_k12(r, t, _q, _p, j, a);
					for (i = 0; i < j; i++) {
						pp_fin_k12_oatep(r, t[i], _q[i], _p[i]);
					}
					pp_exp_k12(r, r);
					break;
				case EP_B12:
					/* r = f_{a,Q}(P). */
					pp_mil_k12(r, t, _q, _p, j, a);
					pp_exp_k12(r, r);
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
			ep2_free(_q[i]);
			ep2_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}
