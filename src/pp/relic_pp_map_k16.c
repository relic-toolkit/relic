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

/**
 * Multiplies by the final lines of the optimal ate pairing over
 * KSS16 curves for m pairs, after the Miller loop of pp_mil_k16().
 *
 * @param[in,out] r			- the result.
 * @param[in,out] t			- the resulting points.
 * @param[in] q				- the points of G_2.
 * @param[in] p				- the points of G_1.
 * @param[in] m				- the number of pairs.
 */
static void pp_fin_k16(fp16_t r, ep4_t *t, ep4_t *q, ep_t *p, int m) {
	if (ep_curve_is_pairf() == EP_K16) {
		fp16_frb(r, r, 3);
		for (int i = 0; i < m; i++) {
			pp_fin_k16_oatep(r, t[i], q[i], p[i]);
		}
	}
}

TMPL_PP_LIN(16, fp4);

/**
 * Records the final lines of the optimal ate pairing over KSS16 curves at the
 * point (1, 1), as pp_fin_k16_oatep() computes them: the line through T and
 * Frob(Q), and then the one through Q and Q.
 *
 * @param[out] t			- the table of lines.
 * @param[out] y			- the coefficients of y_P.
 * @param[in,out] j			- the number of lines in the table.
 * @param[out] l			- a scratch line.
 * @param[in,out] r			- the point T, the multiple of Q.
 * @param[in] q				- the fixed point of G_2.
 * @param[in] e				- the point (1, 1).
 */
static void pp_pre_fin_k16(fp4_t *t, fp4_t *y, int *j, fp16_t l, ep4_t r,
		const ep4_t q, const ep_t e) {
	ep4_t s;

	if (ep_curve_is_pairf() != EP_K16) {
		return;
	}

	ep4_null(s);

	RLC_TRY {
		ep4_new(s);

		ep4_frb(s, q, 1);
		fp16_zero(l);
		pp_add_k16(l, r, s, e);
		pp_rec_k16(t, y, j, l);
		fp16_zero(l);
		pp_dbl_k16(l, s, q, e);
		pp_rec_k16(t, y, j, l);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep4_free(s);
	}
}

/**
 * Multiplies by the final lines of the optimal ate pairing over KSS16 curves,
 * stored by pp_pre_fin_k16(), as pp_map_oatep_k16() and pp_fin_k16_oatep() do
 * after the Miller loop. If g is set, first applies the Frobenius to the
 * result, which a product of pairings does only once.
 *
 * @param[in,out] r			- the result.
 * @param[out] l			- a scratch line.
 * @param[in] t				- the table of lines.
 * @param[in,out] j			- the next line in the table.
 * @param[in] p				- the point of G_1.
 * @param[in] d				- the point of G_1 prepared for doubling lines.
 * @param[in] g				- the flag to take the step on the whole result.
 */
static void pp_fix_fin_k16(fp16_t r, fp16_t l, const fp4_t *t, int *j,
		const ep_t p, const ep_t d, int g) {
	fp16_t u;

	if (ep_curve_is_pairf() != EP_K16) {
		return;
	}

	fp16_null(u);

	RLC_TRY {
		fp16_new(u);

		if (g) {
			fp16_frb(r, r, 3);
		}
		pp_lin_k16(l, t, j, p);
		fp16_frb(u, l, 3);
		fp16_mul_dxs(r, r, u);
		pp_lin_k16(l, t, j, d);
		fp16_mul_dxs(r, r, l);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp16_free(u);
	}
}

/**
 * Hooks of the pairing with a fixed argument: the loop runs over the
 * parameter itself, followed by the final lines of KSS16 curves.
 */
/** @{ */
#define TMPL_PP_FIN_16(R, T, Q, P, M)	pp_fin_k16(R, T, Q, P, M);
#define TMPL_PP_PAR_16(A)			/* No change of the parameter. */
#define TMPL_PP_PRE_FIN_16(T, Y, J, L, R, Q, E)								\
	pp_pre_fin_k16(T, Y, J, L, R, Q, E);
#define TMPL_PP_FIX_FIN_16(R, L, T, J, P, D, G)							\
	pp_fix_fin_k16(R, L, T, J, P, D, G);
/** @} */

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

TMPL_PP_NORM(16, ep4, fp4);

TMPL_PP_MAP_TATEP(16, ep4);

TMPL_PP_MAP_SIM_TATEP(16, ep4);

TMPL_PP_MAP_WEILP(16, ep4);

TMPL_PP_MAP_SIM_WEILP(16, ep4);

TMPL_PP_MAP_OATEP(16, ep4);

TMPL_PP_MAP_SIM_OATEP(16, ep4);

TMPL_PP_MAP_PRE(16, ep4, fp4);

TMPL_PP_MAP_FIX(16, fp4);

TMPL_PP_MAP_SIM_FIX(16, ep4, fp4);
