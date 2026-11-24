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
 * degree 12.
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

/**
 * Multiplies by the final lines of the optimal ate pairing over BN curves, for
 * m pairs, after the Miller loop of pp_mil_k12().
 *
 * @param[in,out] r			- the result.
 * @param[in,out] t			- the resulting points.
 * @param[in] q				- the points of G_2.
 * @param[in] p				- the points of G_1.
 * @param[in] m				- the number of pairs.
 */
static void pp_fin_k12(fp12_t r, ep2_t *t, ep2_t *q, ep_t *p, int m) {
	if (ep_curve_is_pairf() == EP_BN) {
		for (int i = 0; i < m; i++) {
			pp_fin_k12_oatep(r, t[i], q[i], p[i]);
		}
	}
}

TMPL_PP_LIN(12, fp2);

/**
 * Records the final lines of the optimal ate pairing over BN curves, through
 * T and Frob(Q) and then -Frob^2(Q), at the point (1, 1).
 *
 * @param[out] t			- the table of lines.
 * @param[out] y			- the coefficients of y_P.
 * @param[in,out] j			- the number of lines in the table.
 * @param[out] l			- a scratch line.
 * @param[in,out] r			- the point T, the multiple of Q.
 * @param[in] q				- the fixed point of G_2.
 * @param[in] e				- the point (1, 1).
 */
static void pp_pre_fin_k12(fp2_t *t, fp2_t *y, int *j, fp12_t l, ep2_t r,
		const ep2_t q, const ep_t e) {
	ep2_t q1, q2;

	if (ep_curve_is_pairf() != EP_BN) {
		return;
	}

	ep2_null_all(q1, q2);

	RLC_TRY {
		ep2_new_all(q1, q2);

		fp2_set_dig(q1->z, 1);
		fp2_set_dig(q2->z, 1);
		ep2_frb(q1, q, 1);
		ep2_frb(q2, q, 2);
		ep2_neg(q2, q2);

		fp12_zero(l);
		pp_add_k12(l, r, q1, e);
		pp_rec_k12(t, y, j, l);
		fp12_zero(l);
		pp_add_k12(l, r, q2, e);
		pp_rec_k12(t, y, j, l);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep2_free_all(q1, q2);
	}
}

/**
 * Multiplies by the final lines of the optimal ate pairing over BN curves,
 * stored by pp_pre_fin_k12().
 *
 * @param[in,out] r			- the result.
 * @param[out] l			- a scratch line.
 * @param[in] t				- the table of lines.
 * @param[in,out] j			- the next line in the table.
 * @param[in] p				- the point of G_1.
 */
static void pp_fix_fin_k12(fp12_t r, fp12_t l, const fp2_t *t, int *j,
		const ep_t p) {
	if (ep_curve_is_pairf() == EP_BN) {
		pp_lin_k12(l, t, j, p);
		fp12_mul_dxs(r, r, l);
		pp_lin_k12(l, t, j, p);
		fp12_mul_dxs(r, r, l);
	}
}

/**
 * Hooks of the pairing with a fixed argument: the loop parameter 6x + 2 and
 * the final lines of BN curves.
 */
/** @{ */
#define TMPL_PP_FIN_12(R, T, Q, P, M)	pp_fin_k12(R, T, Q, P, M);
#define TMPL_PP_PAR_12(A)													\
	if (ep_curve_is_pairf() == EP_BN) {										\
		bn_mul_dig(A, A, 6);												\
		bn_add_dig(A, A, 2);												\
	}
#define TMPL_PP_PRE_FIN_12(T, Y, J, L, R, Q, E)								\
	pp_pre_fin_k12(T, Y, J, L, R, Q, E);
#define TMPL_PP_FIX_FIN_12(R, L, T, J, P, D, G)							\
	pp_fix_fin_k12(R, L, T, J, P);
/** @} */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_ADD_BASIC(12, ep2, fp2);

TMPL_PP_ADD_PROJC(12, ep2, fp2);

TMPL_PP_ADD_LAZYR(12, ep2, fp2, dv2);

TMPL_PP_ADD_LIT(12, ep2, fp2);

TMPL_PP_DBL_BASIC(12, ep2, fp2);

TMPL_PP_DBL_PROJC(12, ep2, fp2);

TMPL_PP_DBL_LAZYR(12, ep2, fp2, dv2);

TMPL_PP_DBL_LIT(12, ep2, fp2);

TMPL_PP_NORM(12, ep2, fp2);

TMPL_PP_MAP_TATEP(12, ep2);

TMPL_PP_MAP_SIM_TATEP(12, ep2);

TMPL_PP_MAP_WEILP(12, ep2);

TMPL_PP_MAP_SIM_WEILP(12, ep2);

TMPL_PP_MAP_OATEP(12, ep2);

TMPL_PP_MAP_SIM_OATEP(12, ep2);

TMPL_PP_MAP_PRE(12, ep2, fp2);

TMPL_PP_MAP_FIX(12, fp2);

TMPL_PP_MAP_SIM_FIX(12, ep2, fp2);
