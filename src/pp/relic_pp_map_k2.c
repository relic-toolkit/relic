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
 * degree 2.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp.h"
#include "relic_pp_tmpl.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies by a line of degree 2, which is dense, where the templates
 * multiply by the sparse lines of the other degrees.
 */
#define fp2_mul_dxs(C, A, B)	fp2_mul(C, A, B)

/**
 * Hooks of the Tate pairing and of the pairing with a fixed argument: the
 * loop runs over the order of the group minus one, as the points have that
 * order, and there are no final lines.
 */
/** @{ */
#define TMPL_PP_PAR_2(A)													\
	ep_curve_get_ord(A);													\
	bn_sub_dig(A, A, 1);
#define TMPL_PP_FIN_2(R, T, Q, P, M)	/* No final lines. */
#define TMPL_PP_FIX_FIN_2(R, L, T, J, P, D, G)	/* No final lines. */
/** @} */

TMPL_PP_MIL(2, ep);

/**
 * Evaluates at a point the next line of a table of pp_map_pre_k2(), which
 * keeps the coefficient of x_P and the constant term of each line.
 *
 * @param[out] l			- the line.
 * @param[in] t				- the table.
 * @param[in,out] j			- the index of the line in the table.
 * @param[in] p				- the point.
 */
static void pp_lin_k2(fp2_t l, const fp_t *t, int *j, const ep_t p) {
	fp_mul(l[0], t[2 * *j], p->x);
	fp_add(l[0], l[0], t[2 * *j + 1]);
	fp_copy(l[1], p->y);
	(*j)++;
}

/**
 * Computes the lines of the Miller loop of TMPL_PP_MIL_LIT, which runs over
 * the first argument of the pairing and evaluates at the second: the lines
 * of pp_dbl_k2() and pp_add_k2() with their two coefficients swapped.
 *
 * @param[out] l			- the line.
 * @param[out] r			- the resulting point.
 * @param[in] p				- the point to double or to add.
 * @param[in] q				- the point to evaluate at.
 */
/** @{ */
static void pp_dbl_lit_k2(fp2_t l, ep_t r, const ep_t p, const ep_t q) {
	pp_dbl_k2(l, r, p, q);
	dv_swap_sec(l[0], l[1], RLC_FP_DIGS, 1);
}

static void pp_add_lit_k2(fp2_t l, ep_t r, const ep_t p, const ep_t q) {
	pp_add_k2(l, r, p, q);
	dv_swap_sec(l[0], l[1], RLC_FP_DIGS, 1);
}
/** @} */

TMPL_PP_MIL_LIT(2, ep);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_add_k2_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q) {
	fp_t s;
	ep_t t;

	fp_null(s);
	ep_null(t);

	RLC_TRY {
		fp_new(s);
		ep_new(t);

		ep_copy(t, r);
		ep_add_slp_basic(r, s, r, p);
		fp_add(l[0], t->x, q->x);
		fp_mul(l[0], l[0], s);
		fp_sub(l[0], t->y, l[0]);
		fp_neg(l[1], q->y);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(s);
		ep_free(t);
	}
}

void pp_add_k2_projc_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q) {
	fp_t t0, t1, t2, t3, t4, t5;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);

		/* t0 = z1^2. */
		fp_sqr(t0, r->z);

		/* t3 = x2 * z1^2. */
		fp_mul(t3, p->x, t0);

		/* t1 = y2 * z1^3. */
		fp_mul(t1, t0, r->z);
		fp_mul(t1, t1, p->y);

		/* t2 = x1 - t3. */
		fp_sub(t2, r->x, t3);

		/* t4 = y1 - t1. */
		fp_sub(t4, r->y, t1);

		/* l0 = slope * (x2 + xq) - z3 * y2. */
		fp_add(l[0], p->x, q->x);
		fp_mul(l[0], l[0], t4);

		fp_dbl(t0, t3);
		fp_add(t3, t0, t2);
		fp_dbl(t0, t1);
		fp_add(t1, t0, t4);

		fp_mul(r->z, t2, r->z);
		fp_sqr(t0, t2);
		fp_mul(t2, t0, t2);
		fp_mul(t0, t0, t3);
		fp_sqr(t3, t4);

		fp_sub(r->x, t3, t0);
		fp_sub(t0, t0, r->x);
		fp_sub(t0, t0, r->x);
		fp_mul(t5, t0, t4);
		fp_mul(t2, t2, t1);
		fp_sub(t1, t5, t2);

		fp_mul(t5, r->z, p->y);
		fp_sub(l[0], l[0], t5);

		fp_mul(l[1], r->z, q->y);

		fp_hlv(r->y, t1);

		r->coord = EC_JACOB;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);
	}
}

void pp_add_k2_projc_lazyr(fp2_t l, ep_t r, const ep_t p, const ep_t q) {
	fp_t t0, t1, t2, t3, t4, t5;
	dv_t u0, u1;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);
	dv_null(u0);
	dv_null(u1);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);
		dv_new(u0);
		dv_new(u1);

		/* t0 = z1^2. */
		fp_sqr(t0, r->z);

		/* t3 = x2 * z1^2. */
		fp_mul(t3, p->x, t0);

		/* t1 = y2 * z1^3. */
		fp_mul(t1, t0, r->z);
		fp_mul(t1, t1, p->y);

		/* t2 = x1 - t3. */
		fp_sub(t2, r->x, t3);

		/* t4 = y1 - t1. */
		fp_sub(t4, r->y, t1);

		/* l0 = slope * (x2 + xq) - z3 * y2. */
		fp_add(l[0], p->x, q->x);
		fp_muln_low(u0, l[0], t4);

		fp_dbl(t0, t3);
		fp_add(t3, t0, t2);
		fp_dbl(t0, t1);
		fp_add(t1, t0, t4);

		fp_mul(r->z, t2, r->z);
		fp_sqr(t0, t2);
		fp_mul(t2, t0, t2);
		fp_mul(t0, t0, t3);
		fp_sqr(t3, t4);

		fp_sub(r->x, t3, t0);
		fp_sub(t0, t0, r->x);
		fp_sub(t0, t0, r->x);
		fp_mul(t5, t0, t4);
		fp_mul(t2, t2, t1);
		fp_sub(t1, t5, t2);

		fp_muln_low(u1, r->z, p->y);
		fp_subc_low(u0, u0, u1);
		fp_rdcn_low(l[0], u0);

		fp_mul(l[1], r->z, q->y);

		fp_hlv(r->y, t1);

		r->coord = EC_JACOB;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);
		dv_free(u0);
		dv_free(u1);
	}
}

void pp_dbl_k2_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q) {
	fp_t s;
	ep_t t;

	fp_null(s);
	ep_null(t);

	RLC_TRY {
		fp_new(s);
		ep_new(t);

		ep_copy(t, p);
		ep_dbl_slp_basic(r, s, p);
		fp_add(l[0], t->x, q->x);
		fp_mul(l[0], l[0], s);
		fp_sub(l[0], t->y, l[0]);
		fp_copy(l[1], q->y);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(s);
		ep_free(t);
	}
}

void pp_dbl_k2_projc_basic(fp2_t l, ep_t r, const ep_t p, const ep_t q) {
	fp_t t0, t1, t2, t3, t4, t5;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);

		/* dbl-2001-b formulas with alpha for a general a. */
		/* http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b */

		/* t0 = delta = z1^2. */
		fp_sqr(t0, p->z);

		/* t1 = gamma = y1^2. */
		fp_sqr(t1, p->y);

		/* t2 = beta = x1 * y1^2. */
		fp_mul(t2, p->x, t1);

		/* t3 = alpha = 3 * x1^2 + a * z1^4. */
		if (ep_curve_opt_a() == RLC_MIN3) {
			/* Save one multiplication: alpha = 3 * (x1 - z1^2) * (x1 + z1^2). */
			fp_sub(t3, p->x, t0);
			fp_add(t4, p->x, t0);
			fp_mul(t4, t3, t4);
			fp_dbl(t3, t4);
			fp_add(t3, t3, t4);
		} else {
			fp_sqr(t3, p->x);
			fp_dbl(t4, t3);
			fp_add(t3, t3, t4);
			fp_sqr(t4, t0);
			ep_curve_mul_a(t4, t4);
			fp_add(t3, t3, t4);
		}

		fp_dbl(t2, t2);
		fp_dbl(t2, t2);

		/* z3 = (y1 + z1)^2 - gamma - delta. */
		fp_add(r->z, p->y, p->z);
		fp_sqr(r->z, r->z);
		fp_sub(r->z, r->z, t1);
		fp_sub(r->z, r->z, t0);

		/* l0 = 2 * gamma - alpha * (delta * xq + x1). */
		fp_dbl(t1, t1);
		fp_mul(t5, t0, q->x);
		fp_add(t5, t5, p->x);
		fp_mul(t5, t5, t3);
		fp_sub(l[0], t1, t5);

		/* x3 = alpha^2 - 8 * beta. */
		fp_dbl(t5, t2);
		fp_sqr(r->x, t3);
		fp_sub(r->x, r->x, t5);

		/* y3 = alpha * (4 * beta - x3) - 8 * gamma^2. */
		fp_sqr(t4, t1);
		fp_dbl(t4, t4);
		fp_sub(r->y, t2, r->x);
		fp_mul(r->y, r->y, t3);
		fp_sub(r->y, r->y, t4);

		/* l1 = - z3 * delta * yq. */
		fp_mul(l[1], r->z, t0);
		fp_mul(l[1], l[1], q->y);

		r->coord = EC_JACOB;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);
	}
}

void pp_dbl_k2_projc_lazyr(fp2_t l, ep_t r, const ep_t p, const ep_t q) {
	fp_t t0, t1, t2, t3, t4, t5;
	dv_t u0, u1;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);
	fp_null(t5);
	dv_null(u0);
	dv_null(u1);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);
		fp_new(t5);
		dv_new(u0);
		dv_new(u1);

		/* dbl-2001-b formulas with alpha for a general a. */
		/* http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b */

		/* t0 = delta = z1^2. */
		fp_sqr(t0, p->z);

		/* t1 = gamma = y1^2. */
		fp_sqr(t1, p->y);

		/* t2 = beta = x1 * y1^2. */
		fp_mul(t2, p->x, t1);

		/* t3 = alpha = 3 * x1^2 + a * z1^4. */
		if (ep_curve_opt_a() == RLC_MIN3) {
			/* Save one multiplication: alpha = 3 * (x1 - z1^2) * (x1 + z1^2). */
			fp_sub(t3, p->x, t0);
			fp_add(t4, p->x, t0);
			fp_mul(t4, t3, t4);
			fp_dbl(t3, t4);
			fp_add(t3, t3, t4);
		} else {
			fp_sqr(t3, p->x);
			fp_dbl(t4, t3);
			fp_add(t3, t3, t4);
			fp_sqr(t4, t0);
			ep_curve_mul_a(t4, t4);
			fp_add(t3, t3, t4);
		}

		/* t2 = 4 * beta. */
		fp_dbl(t2, t2);
		fp_dbl(t2, t2);

		/* z3 = (y1 + z1)^2 - gamma - delta. */
		fp_add(r->z, p->y, p->z);
		fp_sqr(r->z, r->z);
		fp_sub(r->z, r->z, t1);
		fp_sub(r->z, r->z, t0);

		/* l0 = 2 * gamma - alpha * (delta * xq + x1). */
		fp_dbl(t1, t1);
		fp_mul(t5, t0, q->x);
		fp_add(t5, t5, p->x);
		fp_mul(t5, t5, t3);
		fp_sub(l[0], t1, t5);

		/* x3 = alpha^2 - 8 * beta. */
		fp_dbl(t5, t2);
		fp_sqr(r->x, t3);
		fp_sub(r->x, r->x, t5);

		/* y3 = alpha * (4 * beta - x3) - 8 * gamma^2. */
		fp_sqrn_low(u0, t1);
		fp_addc_low(u0, u0, u0);
		fp_subm_low(r->y, t2, r->x);
		fp_muln_low(u1, r->y, t3);
		fp_subc_low(u1, u1, u0);
		fp_rdcn_low(r->y, u1);

		/* l1 = - z3 * delta * yq. */
		fp_mul(l[1], r->z, t0);
		fp_mul(l[1], l[1], q->y);

		r->coord = EC_JACOB;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
		fp_free(t5);
		dv_free(u0);
		dv_free(u1);
	}
}

void pp_norm_k2(ep_t r, const ep_t p) {
	ep_norm(r, p);
}

TMPL_PP_MAP_MIL(2, ep, tatep);

TMPL_PP_MAP_SIM_MIL(2, ep, tatep);

TMPL_PP_MAP_WEILP(2, ep);

TMPL_PP_MAP_SIM_WEILP(2, ep);

void pp_map_pre_k2(fp_t *t, const ep_t q) {
	fp_t *y = RLC_ALLOCA(fp_t, RLC_PP_TABLE_K2 / 2);
	fp2_t l;
	ep_t r, s, _q, n, e0, e1;
	bn_t a;
	int i, j = 0;
	size_t len = RLC_FP_BITS + 1;
	int8_t b[RLC_FP_BITS + 1];

	if (y == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (i = 0; i < RLC_PP_TABLE_K2 / 2; i++) {
		fp_null(y[i]);
	}
	fp2_null(l);
	ep_null_all(r, s, _q, n, e0, e1);
	bn_null(a);

	RLC_TRY {
		for (i = 0; i < RLC_PP_TABLE_K2 / 2; i++) {
			fp_new(y[i]);
		}
		fp2_new(l);
		ep_new_all(r, s, _q, n, e0, e1);
		bn_new(a);

		/* A table starting with two zeros stands for the point at infinity,
		 * as the constant term of a real line is not zero. */
		fp_zero(t[0]);
		fp_zero(t[1]);
		if (!ep_is_infty(q)) {
			/* The pairing is symmetric, so the loop runs over Q instead. The
			 * lines are c_j + c_x * x + c_y * y * i, evaluated at (0, 1) and
			 * at (1, 1) from the same point to separate c_j from c_x. */
			ep_norm(_q, q);
			ep_neg(n, _q);
			ep_copy(r, _q);
			fp_zero(e0->x);
			fp_set_dig(e0->y, 1);
			fp_set_dig(e0->z, 1);
			e0->coord = EC_AFFIN;
			fp_set_dig(e1->x, 1);
			fp_set_dig(e1->y, 1);
			fp_set_dig(e1->z, 1);
			e1->coord = EC_AFFIN;

			ep_curve_get_ord(a);
			bn_sub_dig(a, a, 1);
			bn_rec_naf(b, &len, a, 2);
			for (i = len - 2; i >= 0; i--) {
				for (int k = 0; k < 2; k++) {
					if (k == 1 && b[i] == 0) {
						break;
					}
					if (2 * j + 2 > RLC_PP_TABLE_K2) {
						RLC_THROW(ERR_NO_BUFFER);
						break;
					}
					ep_copy(s, r);
					if (k == 0) {
						pp_dbl_k2(l, s, s, e0);
					} else {
						pp_add_k2(l, s, b[i] > 0 ? _q : n, e0);
					}
					fp_copy(t[2 * j + 1], l[0]);
					fp_copy(y[j], l[1]);
					if (k == 0) {
						pp_dbl_k2(l, r, r, e1);
					} else {
						pp_add_k2(l, r, b[i] > 0 ? _q : n, e1);
					}
					fp_sub(t[2 * j], l[0], t[2 * j + 1]);
					j++;
				}
			}

			/* Divide each line by its coefficient of y. */
			fp_inv_sim(y, (const fp_t *)y, j);
			for (i = 0; i < j; i++) {
				fp_mul(t[2 * i], t[2 * i], y[i]);
				fp_mul(t[2 * i + 1], t[2 * i + 1], y[i]);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < RLC_PP_TABLE_K2 / 2; i++) {
			fp_free(y[i]);
		}
		fp2_free(l);
		ep_free_all(r, s, _q, n, e0, e1);
		bn_free(a);
		RLC_FREE(y);
	}
}

TMPL_PP_MAP_FIX(2, fp);

TMPL_PP_MAP_SIM_FIX(2, ep, fp);
