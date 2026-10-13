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
 * Implementation of the line functions and pairings for curves with embedding
 * degree 54.
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

TMPL_PP_MIL(54, ep9);

TMPL_PP_MIL_LIT(54, ep9);

/**
 * Multiplies the result of the Miller loop over the parameter by the final
 * lines of the optimal ate pairing, so that it becomes
 * f_{a,Q}^3 * l_{T,T} * l_{T,2T} * l_{Frob^10(Q),Frob(Q)}, all evaluated at P.
 *
 * @param[in,out] r			- the result.
 * @param[in] t				- the points aQ produced by the loop.
 * @param[in] q				- the vector of affine points in G_2.
 * @param[in] p				- the vector of affine points in G_1.
 * @param[in] m				- the number of pairings to evaluate.
 */
static void pp_fin_k54(fp54_t r, ep9_t *t, ep9_t *q, ep_t *p, int m) {
	fp54_t l;
	ep9_t s, u;
	ep_t _p;
	int j;

	fp54_null(l);
	ep9_null_all(s, u);
	ep_null(_p);

	RLC_TRY {
		fp54_new(l);
		ep9_new_all(s, u);
		ep_new(_p);

		/* Compute f^3. */
		fp54_sqr(l, r);
		fp54_mul(r, r, l);

		for (j = 0; j < m; j++) {
			/* Multiply by the lines through T and 2T. */
			TMPL_PP_MIL_P_54(_p, p[j])
			fp54_zero(l);
			pp_dbl_k54(l, s, t[j], _p);
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
		ep9_free_all(s, u);
		ep_free(_p);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_ADD_BASIC(54, ep9, fp9);

TMPL_PP_ADD_PROJC(54, ep9, fp9);

TMPL_PP_ADD_LAZYR(54, ep9, fp9, dv9);

TMPL_PP_ADD_LIT(54, ep9, fp9);

TMPL_PP_DBL_BASIC(54, ep9, fp9);

TMPL_PP_DBL_PROJC(54, ep9, fp9);

TMPL_PP_DBL_LAZYR(54, ep9, fp9, dv9);

TMPL_PP_DBL_LIT(54, ep9, fp9);

TMPL_PP_NORM(54, ep9, fp9);

TMPL_PP_MAP_TATEP(54, ep9);

TMPL_PP_MAP_SIM_TATEP(54, ep9);

TMPL_PP_MAP_WEILP(54, ep9);

TMPL_PP_MAP_SIM_WEILP(54, ep9);

TMPL_PP_MAP_OATEP(54, ep9, EP_SG54);

TMPL_PP_MAP_SIM_OATEP(54, ep9, EP_SG54);
