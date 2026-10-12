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

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_ADD_BASIC(12, ep2, fp2);

TMPL_PP_ADD_PROJC(12, ep2, fp2);

TMPL_PP_ADD_LAZYR(12, ep2, fp2, dv2);

TMPL_PP_ADD_LIT(12, ep2, fp2);

TMPL_PP_DBL_BASIC(12, ep2, fp2);

void pp_dbl_k12_projc_basic(fp12_t l, ep2_t r, const ep2_t q, const ep_t p) {
	fp2_t t0, t1, t2, t3, t4, t5, t6;
	int one = 1, zero = 0;

	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);
	fp2_null(t3);
	fp2_null(t4);
	fp2_null(t5);
	fp2_null(t6);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);
		fp2_new(t4);
		fp2_new(t5);
		fp2_new(t6);

		if (ep2_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* A = x1^2. */
		fp2_sqr(t0, q->x);
		/* B = y1^2. */
		fp2_sqr(t1, q->y);		
		/* t2 = C = z1^2. */
		fp2_sqr(t2, q->z);

		/* The fast path below hardcodes b' = 1 - i, which holds for b = 2
		 * with a D-type twist by xi = 1 + i, so check b' itself. */
		fp_neg(t3[0], ep2_curve_get_b()[1]);
		if (ep_curve_opt_b() == RLC_TWO &&
				fp_cmp_dig(ep2_curve_get_b()[0], 1) == RLC_EQ &&
				fp_cmp_dig(t3[0], 1) == RLC_EQ) {
			/* t3 = E = 3b'C = 3C * (1 - i). */
			fp2_dbl(t3, t2);
			fp2_add(t2, t2, t3);
			fp_add(t3[0], t2[0], t2[1]);
			fp_sub(t3[1], t2[1], t2[0]);
			/* t4 = A = (x1 * y1)/2. */
			fp2_mul(t4, q->x, q->y);
			fp_hlv(t4[0], t4[0]);
			fp_hlv(t4[1], t4[1]);
			/* t2 = F = 3E. */
			fp2_dbl(t2, t3);
			fp2_add(t2, t3, t2);
			/* x3 = A * (B - F). */
			fp2_sub(r->x, t1, t2);
			fp2_mul(r->x, r->x, t4);
			/* t2 = G = (B + F)/2. */
			fp2_add(t2, t1, t2);
			fp_hlv(t2[0], t2[0]);
			fp_hlv(t2[1], t2[1]);
			/* y3 = G^2 - 3E^2. */
			fp2_sqr(t2, t2);
			fp2_sqr(t4, t3);
			/* t5 = y1 * z1. */
			fp2_mul(t5, q->y, q->z);
			fp2_dbl(r->y, t4);
			fp2_add(r->y, r->y, t4);
			fp2_sub(r->y, t2, r->y);

			/* t2 = H = 2 * y1 * z1. */
			fp2_dbl(t5, t5);
			/* z3 = B * H. */
			fp2_mul(r->z, t1, t5);
		} else {
			/* D = 3bC, general b. */
			fp2_dbl(t3, t2);
			fp2_add(t3, t3, t2);
			ep2_curve_mul_b(t3, t3);
			/* E = (x1 + y1)^2 - A - B. */
			fp2_add(t4, q->x, q->y);
			fp2_sqr(t4, t4);
			fp2_sub(t4, t4, t0);
			fp2_sub(t4, t4, t1);

			/* F = (y1 + z1)^2 - B - C. */
			fp2_add(t5, q->y, q->z);
			fp2_sqr(t5, t5);
			fp2_sub(t5, t5, t1);
			fp2_sub(t5, t5, t2);

			/* G = 3D. */
			fp2_dbl(t6, t3);
			fp2_add(t6, t6, t3);

			/* x3 = E * (B - G). */
			fp2_sub(r->x, t1, t6);
			fp2_mul(r->x, r->x, t4);

			/* y3 = (B + G)^2 -12D^2. */
			fp2_add(t6, t6, t1);
			fp2_sqr(t6, t6);
			fp2_sqr(t2, t3);
			fp2_dbl(r->y, t2);
			fp2_dbl(t2, r->y);
			fp2_dbl(r->y, t2);
			fp2_add(r->y, r->y, t2);
			fp2_sub(r->y, t6, r->y);

			/* z3 = 4B * F. */
			fp2_dbl(r->z, t1);
			fp2_dbl(r->z, r->z);
			fp2_mul(r->z, r->z, t5);
		}
		/* l11 = D - B. */
		fp2_sub(l[one][one], t3, t1);

		/* l10 = (3 * xp) * A. */
		fp_mul(l[one][zero][0], p->x, t0[0]);
		fp_mul(l[one][zero][1], p->x, t0[1]);

		/* l00 = F * (-yp). */
		fp_mul(l[zero][zero][0], t5[0], p->y);
		fp_mul(l[zero][zero][1], t5[1], p->y);

		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
		fp2_free(t3);
		fp2_free(t4);
		fp2_free(t5);
		fp2_free(t6);
	}
}

void pp_dbl_k12_projc_lazyr(fp12_t l, ep2_t r, const ep2_t q, const ep_t p) {
	fp2_t t0, t1, t2, t3, t4, t5, t6;
	dv2_t u0, u1;
	int one = 1, zero = 0;

	fp2_null(t0);
	fp2_null(t1);
	fp2_null(t2);
	fp2_null(t3);
	fp2_null(t4);
	fp2_null(t5);
	fp2_null(t6);
	dv2_null(u0);
	dv2_null(u1);

	RLC_TRY {
		fp2_new(t0);
		fp2_new(t1);
		fp2_new(t2);
		fp2_new(t3);
		fp2_new(t4);
		fp2_new(t5);
		fp2_new(t6);
		dv2_new(u0);
		dv2_new(u1);

		if (ep2_curve_is_twist() == RLC_EP_MTYPE) {
			one ^= 1;
			zero ^= 1;
		}

		/* t0 = x1^2. */
		fp2_sqr(t0, q->x);
		/* B = y1^2. */
		fp2_sqr(t1, q->y);
		/* C = z1^2. */
		fp2_sqr(t2, q->z);
		/* t6 = B + C. */
		fp2_add(t6, t1, t2);
		fp2_dbl(t3, t2);
		fp2_add(t3, t3, t2);

		/* The fast path below hardcodes b' = 1 - i, which holds for b = 2
		 * with a D-type twist by xi = 1 + i, so check b' itself. */
		fp_neg(t4[0], ep2_curve_get_b()[1]);
		if (ep_curve_opt_b() == RLC_TWO &&
				fp_cmp_dig(ep2_curve_get_b()[0], 1) == RLC_EQ &&
				fp_cmp_dig(t4[0], 1) == RLC_EQ) {
			/* t2 = E = 3b'C = 3C * (1 - i). */
			fp_add(t2[0], t3[0], t3[1]);
			fp_sub(t2[1], t3[1], t3[0]);

			/* t4 = A = (x1 * y1)/2. */
			fp2_mul(t4, q->x, q->y);
			fp_hlv(t4[0], t4[0]);
			fp_hlv(t4[1], t4[1]);

			/* H = (Y + Z)^2 - B - C. */
			fp2_add(t5, q->y, q->z);
			fp2_sqr(t5, t5);
			fp2_sub(t5, t5, t6);

			/* t3 = F = 3E. */
			fp2_dbl(t3, t2);
			fp2_add(t3, t3, t2);
			
			/* x3 = A * (B - F). */
			fp2_sub(r->x, t1, t3);
			fp2_mul(r->x, r->x, t4);

			/* G = (B + F)/2. */
			fp2_add(t3, t1, t3);
			fp_hlv(t3[0], t3[0]);
			fp_hlv(t3[1], t3[1]);

			/* y3 = G^2 - 3E^2. */
			fp2_sqrn_low(u0, t2);
			fp2_addd_low(u1, u0, u0);
			fp2_addd_low(u1, u1, u0);
			fp2_sqrn_low(u0, t3);
			fp2_subc_low(u0, u0, u1);
			fp2_rdcn_low(r->y, u0);

			/* z3 = B * H. */
			fp2_mul(r->z, t1, t5);

			/* l11 = E - B. */
			fp2_sub(l[one][one], t2, t1);
		} else {
			/* D = 3bC, for general b. */
			ep2_curve_mul_b(t3, t3);
			/* E = (x1 + y1)^2 - A - B. */
			fp2_add(t4, q->x, q->y);
			fp2_sqr(t4, t4);
			fp2_sub(t4, t4, t0);
			fp2_sub(t4, t4, t1);

			/* F = (y1 + z1)^2 - B - C. */
			fp2_add(t5, q->y, q->z);
			fp2_sqr(t5, t5);
			fp2_sub(t5, t5, t6);

			/* G = 3D. */
			fp2_dbl(t6, t3);
			fp2_add(t6, t6, t3);

			/* x3 = E * (B - G). */
			fp2_sub(r->x, t1, t6);
			fp2_mul(r->x, r->x, t4);

			/* y3 = (B + G)^2 - 3(2D)^2, reduced once. */
			fp2_add(t6, t6, t1);
			fp2_dbl(t2, t3);
			fp2_sqrn_low(u1, t2);
			fp2_addc_low(u0, u1, u1);
			fp2_addc_low(u1, u0, u1);
			fp2_sqrn_low(u0, t6);
			fp2_subc_low(u0, u0, u1);
			fp2_rdcn_low(r->y, u0);

			/* z3 = 4B * F. */
			fp2_dbl(r->z, t1);
			fp2_dbl(r->z, r->z);
			fp2_mul(r->z, r->z, t5);

			/* l00 = D - B. */
			fp2_sub(l[one][one], t3, t1);
		}
		/* l01 = F * (-yp). */
		fp_mul(l[zero][zero][0], t5[0], p->y);
		fp_mul(l[zero][zero][1], t5[1], p->y);

		/* l10 = (3 * xp) * A. */
		fp_mul(l[one][zero][0], p->x, t0[0]);
		fp_mul(l[one][zero][1], p->x, t0[1]);

		r->coord = PROJC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(t0);
		fp2_free(t1);
		fp2_free(t2);
		fp2_free(t3);
		fp2_free(t4);
		fp2_free(t5);
		fp2_free(t6);
		dv2_free(u0);
		dv2_free(u1);
	}
}

TMPL_PP_DBL_LIT(12, ep2, fp2);

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
