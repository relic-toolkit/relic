/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * degree 18.
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

TMPL_PP_MIL(18, ep3);

TMPL_PP_MIL_LIT(18, ep3);

/**
 * Compute the final lines for optimal ate pairings.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] q				- the first point of the pairing, in G_2.
 * @param[in] p				- the second point of the pairing, in G_1.
 * @param[in] f				- the flag to correct for the curve family.
 */
static void pp_fin_k18_oatep(fp18_t r, ep3_t t, const ep3_t q, const ep_t p,
		int f) {
    fp18_t u, v;
    ep3_t _q;
    ep_t _p;

    fp18_null(u);
    fp18_null(v);
    ep3_null(_q);
    ep_null(_p);

    RLC_TRY {
        fp18_new(u);
        fp18_new(v);
        ep3_new(_q);
        ep_new(_p);

		/* Compute additional line function. */
		fp18_zero(u);
		fp18_zero(v);

		switch (ep_curve_is_pairf()) {
			case EP_K18:
				TMPL_PP_MIL_P_18(_p, p)
				/* _q = 3*p*Q. */
		        pp_dbl_k18(u, _q, q, _p);
		        pp_add_k18(v, _q, q, p);
		        pp_norm_k18(_q, _q);
		        fp18_mul_dxs(u, u, v);
		        fp18_frb(u, u, 1);
		        fp18_mul(r, r, u);
		        ep3_frb(_q, _q, 1);
		        pp_add_k18(u, t, _q, p);
		        fp18_mul_dxs(r, r, u);
				break;
			case EP_SG18:
				if (f == 1) {
					fp18_frb(u, r, 3);
					fp18_mul(r, r, u);
				}
				ep3_frb(t, t, 3);
				ep3_frb(_q, q, 2);
				pp_add_k18(v, t, _q, p);
				fp18_mul_dxs(r, r, v);
				break;
		}
    } RLC_CATCH_ANY {
        RLC_THROW(ERR_CAUGHT);
    } RLC_FINALLY {
        fp18_free(u);
        fp18_free(v);
        ep3_free(_q);
        ep_free(_p);
    }
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_ADD_BASIC(18, ep3, fp3);

TMPL_PP_ADD_PROJC(18, ep3, fp3);

TMPL_PP_ADD_LAZYR(18, ep3, fp3, dv3);

TMPL_PP_ADD_LIT(18, ep3, fp3);

TMPL_PP_DBL_BASIC(18, ep3, fp3);

TMPL_PP_DBL_PROJC(18, ep3, fp3);

TMPL_PP_DBL_LAZYR(18, ep3, fp3, dv3);

TMPL_PP_DBL_LIT(18, ep3, fp3);

TMPL_PP_NORM(18, ep3, fp3);

TMPL_PP_MAP_TATEP(18, ep3);

TMPL_PP_MAP_SIM_TATEP(18, ep3);

TMPL_PP_MAP_WEILP(18, ep3);

TMPL_PP_MAP_SIM_WEILP(18, ep3);

void pp_map_oatep_k18(fp18_t r, const ep_t p, const ep3_t q) {
	ep_t _p[1];
	ep3_t t[1], _q[1];
	bn_t a;

	ep_null(_p[0]);
	ep3_null(_q[0]);
	ep3_null(t[0]);
	bn_null(a);

	RLC_TRY {
		ep_new(_p[0]);
		ep3_new(_q[0]);
		ep3_new(t[0]);
		bn_new(a);

		fp_prime_get_par(a);
		fp18_set_dig(r, 1);

		ep_norm(_p[0], p);
		ep3_norm(_q[0], q);

		if (!ep_is_infty(_p[0]) && !ep3_is_infty(_q[0])) {
			switch (ep_curve_is_pairf()) {
				case EP_K18:
					/* r = f_{a,Q}(P). */
					pp_mil_k18(r, t, _q, _p, 1, a);
					pp_fin_k18_oatep(r, t[0], _q[0], _p[0], 0);
					pp_exp_k18(r, r);
					break;
				case EP_SG18:
					/* r = f_{a,Q}(P). */
					pp_mil_k18(r, t, _q, _p, 1, a);
					pp_fin_k18_oatep(r, t[0], _q[0], _p[0], 1);
					pp_exp_k18(r, r);
					break;
				case EP_FM18:
					/* r = f_{a,Q}(P). */
					pp_mil_k18(r, t, _q, _p, 1, a);
					pp_exp_k18(r, r);
					break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep3_free(_q[0]);
		ep3_free(t[0]);
		bn_free(a);
	}
}

void pp_map_sim_oatep_k18(fp18_t r, const ep_t *p, const ep3_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep3_t *t = RLC_ALLOCA(ep3_t, m), *_q = RLC_ALLOCA(ep3_t, m);
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
		ep3_null(_q[i]);
		ep3_null(t[i]);
	}

	RLC_TRY {
		bn_new(a);
		for (i = 0; i < m; i++) {
			ep_new(_p[i]);
			ep3_new(_q[i]);
			ep3_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep3_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep3_norm(_q[j++], q[i]);
			}
		}

		fp_prime_get_par(a);
		fp18_set_dig(r, 1);

		if (j > 0) {
			switch (ep_curve_is_pairf()) {
				case EP_K18:
					/* r = f_{a,Q}(P). */
					pp_mil_k18(r, t, _q, _p, j, a);
					for (i = 0; i < j; i++) {
						pp_fin_k18_oatep(r, t[i], _q[i], _p[i], 0);
					}
					pp_exp_k18(r, r);
					break;
				case EP_SG18:
					/* r = f_{a,Q}(P). */
					pp_mil_k18(r, t, _q, _p, j, a);
					for (i = 0; i < j; i++) {
						/* Apply Frobenius only once. */
						pp_fin_k18_oatep(r, t[i], _q[i], _p[i], i == 0);
					}
					pp_exp_k18(r, r);
					break;
				case EP_FM18:
					/* r = f_{a,Q}(P). */
					pp_mil_k18(r, t, _q, _p, j, a);
					pp_exp_k18(r, r);
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
			ep3_free(_q[i]);
			ep3_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}
