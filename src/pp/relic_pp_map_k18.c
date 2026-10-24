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

/**
 * Multiplies by the final lines of the optimal ate pairing over
 * KSS and SG curves for m pairs, after the Miller loop of pp_mil_k18().
 *
 * @param[in,out] r			- the result.
 * @param[in,out] t			- the resulting points.
 * @param[in] q				- the points of G_2.
 * @param[in] p				- the points of G_1.
 * @param[in] m				- the number of pairs.
 */
static void pp_fin_k18(fp18_t r, ep3_t *t, ep3_t *q, ep_t *p, int m) {
	for (int i = 0; i < m; i++) {
		switch (ep_curve_is_pairf()) {
			case EP_K18:
				pp_fin_k18_oatep(r, t[i], q[i], p[i], 0);
				break;
			case EP_SG18:
				/* Apply Frobenius only once. */
				pp_fin_k18_oatep(r, t[i], q[i], p[i], i == 0);
				break;
		}
	}
}

TMPL_PP_LIN(18, fp3);

/**
 * Records the final lines of the optimal ate pairing over KSS and SG curves
 * at the point (1, 1), as pp_fin_k18_oatep() computes them: for KSS curves,
 * the lines through Q and Q and through 2Q and Q, and then the one through T
 * and Frob(3Q); for SG curves, the line through Frob^3(T) and Frob^2(Q).
 *
 * @param[out] t			- the table of lines.
 * @param[out] y			- the coefficients of y_P.
 * @param[in,out] j			- the number of lines in the table.
 * @param[out] l			- a scratch line.
 * @param[in,out] r			- the point T, the multiple of Q.
 * @param[in] q				- the fixed point of G_2.
 * @param[in] e				- the point (1, 1).
 */
static void pp_pre_fin_k18(fp3_t *t, fp3_t *y, int *j, fp18_t l, ep3_t r,
		const ep3_t q, const ep_t e) {
	ep3_t s;

	ep3_null(s);

	RLC_TRY {
		ep3_new(s);

		switch (ep_curve_is_pairf()) {
			case EP_K18:
				fp18_zero(l);
				pp_dbl_k18(l, s, q, e);
				pp_rec_k18(t, y, j, l);
				fp18_zero(l);
				pp_add_k18(l, s, q, e);
				pp_rec_k18(t, y, j, l);
				pp_norm_k18(s, s);
				ep3_frb(s, s, 1);
				fp18_zero(l);
				pp_add_k18(l, r, s, e);
				pp_rec_k18(t, y, j, l);
				break;
			case EP_SG18:
				ep3_frb(r, r, 3);
				ep3_frb(s, q, 2);
				fp18_zero(l);
				pp_add_k18(l, r, s, e);
				pp_rec_k18(t, y, j, l);
				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		ep3_free(s);
	}
}

/**
 * Multiplies by the final lines of the optimal ate pairing over KSS and SG
 * curves, stored by pp_pre_fin_k18(), as pp_fin_k18_oatep() does. If g is
 * set, SG18 curves first multiply the result by its Frobenius, which a product
 * of pairings does only once.
 *
 * @param[in,out] r			- the result.
 * @param[out] l			- a scratch line.
 * @param[in] t				- the table of lines.
 * @param[in,out] j			- the next line in the table.
 * @param[in] p				- the point of G_1.
 * @param[in] d				- the point of G_1 prepared for doubling lines.
 * @param[in] g				- the flag to take the step on the whole result.
 */
static void pp_fix_fin_k18(fp18_t r, fp18_t l, const fp3_t *t, int *j,
		const ep_t p, const ep_t d, int g) {
	fp18_t u;

	fp18_null(u);

	RLC_TRY {
		fp18_new(u);

		switch (ep_curve_is_pairf()) {
			case EP_K18:
				pp_lin_k18(l, t, j, d);
				fp18_copy(u, l);
				pp_lin_k18(l, t, j, p);
				fp18_mul_dxs(u, u, l);
				fp18_frb(u, u, 1);
				fp18_mul(r, r, u);
				pp_lin_k18(l, t, j, p);
				fp18_mul_dxs(r, r, l);
				break;
			case EP_SG18:
				if (g) {
					fp18_frb(u, r, 3);
					fp18_mul(r, r, u);
				}
				pp_lin_k18(l, t, j, p);
				fp18_mul_dxs(r, r, l);
				break;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp18_free(u);
	}
}

/**
 * Hooks of the pairing with a fixed argument: the loop runs over the
 * parameter itself, followed by the final lines of KSS and SG curves.
 */
/** @{ */
#define TMPL_PP_FIN_18(R, T, Q, P, M)	pp_fin_k18(R, T, Q, P, M);
#define TMPL_PP_PAR_18(A)			/* No change of the parameter. */
#define TMPL_PP_PRE_FIN_18(T, Y, J, L, R, Q, E)								\
	pp_pre_fin_k18(T, Y, J, L, R, Q, E);
#define TMPL_PP_FIX_FIN_18(R, L, T, J, P, D, G)							\
	pp_fix_fin_k18(R, L, T, J, P, D, G);
/** @} */

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

TMPL_PP_MAP_OATEP(18, ep3);

TMPL_PP_MAP_SIM_OATEP(18, ep3);

TMPL_PP_MAP_PRE(18, ep3, fp3);

TMPL_PP_MAP_FIX(18, fp3);

TMPL_PP_MAP_SIM_FIX(18, ep3, fp3);
