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
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Compute the Miller loop for pairings of type G_2 x G_1 over the bits of a
 * given parameter.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] p				- the first pairing argument in affine coordinates.
 * @param[in] q				- the second pairing argument in affine coordinates.
 * @param[in] m 			- the number of pairings to evaluate.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_k2(fp2_t r, ep_t *t, ep_t *p, ep_t *q, int m, bn_t a) {
	fp2_t l;
	ep_t *_q = RLC_ALLOCA(ep_t, m);
	int i, j;
	size_t len = bn_bits(a) + 1;
	int8_t b[RLC_FP_BITS + 1];

	fp2_null(l);

	if (_q == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (j = 0; j < m; j++) {
		ep_null(_q[j]);
	}

	RLC_TRY {
		fp2_new(l);
		for (j = 0; j < m; j++) {
			ep_new(_q[j]);
			ep_copy(t[j], p[j]);
			ep_neg(_q[j], q[j]);
		}

		fp2_zero(l);
		bn_rec_naf(b, &len, a, 2);
		for (i = len - 2; i >= 0; i--) {
			fp2_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_k2(l, t[j], t[j], _q[j]);
				fp2_mul(r, r, l);
				if (b[i] > 0) {
					pp_add_k2(l, t[j], p[j], q[j]);
					fp2_mul(r, r, l);
				}
				if (b[i] < 0) {
					ep_neg(p[j], p[j]);
					pp_add_k2(l, t[j], p[j], q[j]);
					ep_neg(p[j], p[j]);
					fp2_mul(r, r, l);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(l);
		for (j = 0; j < m; j++) {
			ep_free(_q[j]);
		}
		RLC_FREE(_q);
	}
}

/**
 * Compute the Miller loop for pairings of type G_1 x G_2 over the bits of a
 * given parameter.
 *
 * @param[out] r			- the result.
 * @param[out] t			- the resulting point.
 * @param[in] p				- the first pairing argument in affine coordinates.
 * @param[in] q				- the second pairing argument in affine coordinates.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_lit_k2(fp2_t r, ep_t *t, ep_t *p, ep_t *q, int m, bn_t a) {
	fp2_t l, _l;
	ep_t *_q = RLC_ALLOCA(ep_t, m);
	int i, j;
	size_t len = bn_bits(a) + 1;
	int8_t b[RLC_FP_BITS + 1];

	fp2_null(l);
	fp2_null(_l);

	if (_q == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (j = 0; j < m; j++) {
		ep_null(_q[j]);
	}

	RLC_TRY {
		fp2_new(l);
		fp2_new(_l);
		for (j = 0; j < m; j++) {
			ep_new(_q[j]);
			ep_copy(t[j], p[j]);
			ep_neg(_q[j], q[j]);
		}

		fp2_zero(l);
		bn_rec_naf(b, &len, a, 2);
		for (i = len - 2; i >= 0; i--) {
			fp2_sqr(r, r);
			for (j = 0; j < m; j++) {
				pp_dbl_k2(l, t[j], t[j], _q[j]);
				fp_copy(_l[0], l[1]);
				fp_copy(_l[1], l[0]);
				fp2_mul(r, r, _l);
				if (b[i] > 0) {
					pp_add_k2(l, t[j], p[j], q[j]);
					fp_copy(_l[0], l[1]);
					fp_copy(_l[1], l[0]);
					fp2_mul(r, r, _l);
				}
				if (b[i] < 0) {
					ep_neg(p[j], p[j]);
					pp_add_k2(l, t[j], p[j], q[j]);
					ep_neg(p[j], p[j]);
					fp_copy(_l[0], l[1]);
					fp_copy(_l[1], l[0]);
					fp2_mul(r, r, _l);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(l);
		fp2_free(_l);
		for (j = 0; j < m; j++) {
			ep_free(_q[j]);
		}
		RLC_FREE(_q);
	}
}

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

void pp_map_tatep_k2(fp2_t r, const ep_t p, const ep_t q) {
	ep_t _p[1], _q[1], t[1];
	bn_t n;

	ep_null(_p[0]);
	ep_null(_q[0]);
	ep_null(t[0]);
	bn_null(n);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(_q[0]);
		ep_new(t[0]);
		bn_new(n);

		ep_norm(_p[0], p);
		ep_norm(_q[0], q);
		ep_curve_get_ord(n);
		/* Since p has order n, we do not have to perform last iteration. */
		bn_sub_dig(n, n, 1);
		fp2_set_dig(r, 1);

		if (!ep_is_infty(p) && !ep_is_infty(q)) {
			pp_mil_k2(r, t, _p, _q, 1, n);
			pp_exp_k2(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(_q[0]);
		ep_free(t[0]);
		bn_free(n);
	}
}

void pp_map_sim_tatep_k2(fp2_t r, const ep_t *p, const ep_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m),
			*_q = RLC_ALLOCA(ep_t, m), *t = RLC_ALLOCA(ep_t, m);
	bn_t n;
	int i, j;

	bn_null(n);

	if (_p == NULL || _q == NULL || t == NULL) {
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (i = 0; i < m; i++) {
		ep_null(_p[i]);
		ep_null(_q[i]);
		ep_null(t[i]);
	}

	RLC_TRY {
		bn_new(n);
		for (i = 0; i < m; i++) {
			ep_new(_p[i]);
			ep_new(_q[i]);
			ep_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep_norm(_q[j++], q[i]);
			}
		}

		ep_curve_get_ord(n);
		bn_sub_dig(n, n, 1);
		fp2_set_dig(r, 1);
		if (j > 0) {
			pp_mil_k2(r, t, _p, _q, j, n);
			pp_exp_k2(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep_free(_q[i]);
			ep_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}

void pp_map_weilp_k2(fp2_t r, const ep_t p, const ep_t q) {
	ep_t _p[1], _q[1], t0[1], t1[1];
	fp2_t r0, r1;
	bn_t n;

	ep_null(_p[0]);
	ep_null(_q[0]);
	ep_null(t0[0]);
	ep_null(t1[0]);
	fp2_null(r0);
	fp2_null(r1);
	bn_null(n);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(_q[0]);
		ep_new(t0[0]);
		ep_new(t1[0]);
		fp2_new(r0);
		fp2_new(r1);
		bn_new(n);

		ep_norm(_p[0], p);
		ep_norm(_q[0], q);
		ep_curve_get_ord(n);
		/* Since p has order n, we do not have to perform last iteration. */
		bn_sub_dig(n, n, 1);
		fp2_set_dig(r0, 1);
		fp2_set_dig(r1, 1);

		if (!ep_is_infty(_p[0]) && !ep_is_infty(_q[0])) {
			pp_mil_lit_k2(r0, t0, _p, _q, 1, n);
			pp_mil_k2(r1, t1, _q, _p, 1, n);
			fp2_inv(r1, r1);
			fp2_mul(r0, r0, r1);
			fp2_inv(r1, r0);
			fp2_inv_cyc(r0, r0);
		}
		fp2_mul(r, r0, r1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(_q[0]);
		ep_free(t0[0]);
		ep_free(t1[0]);
		fp2_free(r0);
		fp2_free(r1);
		bn_free(n);
	}
}

void pp_map_sim_weilp_k2(fp2_t r, const ep_t *p, const ep_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m),
			*_q = RLC_ALLOCA(ep_t, m),
			*t0 = RLC_ALLOCA(ep_t, m), *t1 = RLC_ALLOCA(ep_t, m);
	fp2_t r0, r1;
	bn_t n;
	int i, j;

	fp2_null(r0);
	fp2_null(r1);
	bn_null(n);

	if (_p == NULL || _q == NULL || t0 == NULL || t1 == NULL) {
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t0);
		RLC_FREE(t1);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (i = 0; i < m; i++) {
		ep_null(_p[i]);
		ep_null(_q[i]);
		ep_null(t0[i]);
		ep_null(t1[i]);
	}

	RLC_TRY {
		fp2_new(r0);
		fp2_new(r1);
		bn_new(n);
		for (i = 0; i < m; i++) {
			ep_new(_p[i]);
			ep_new(_q[i]);
			ep_new(t0[i]);
			ep_new(t1[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep_norm(_q[j++], q[i]);
			}
		}

		ep_curve_get_ord(n);
		bn_sub_dig(n, n, 1);
		fp2_set_dig(r0, 1);
		fp2_set_dig(r1, 1);

		if (j > 0) {
			pp_mil_lit_k2(r0, t0, _p, _q, j, n);
			pp_mil_k2(r1, t1, _q, _p, j, n);
			fp2_inv(r1, r1);
			fp2_mul(r0, r0, r1);
			fp2_inv(r1, r0);
			fp2_inv_cyc(r0, r0);
		}
		fp2_mul(r, r0, r1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(r0);
		fp2_free(r1);
		bn_free(n);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep_free(_q[i]);
			ep_free(t0[i]);
			ep_free(t1[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t0);
		RLC_FREE(t1);
	}
}

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

void pp_map_fix_k2(fp2_t r, const ep_t p, const fp_t *t) {
	fp2_t l;
	ep_t _p, d;
	bn_t a;
	int i, j = 0;
	size_t len = RLC_FP_BITS + 1;
	int8_t b[RLC_FP_BITS + 1];

	fp2_null(l);
	ep_null_all(_p, d);
	bn_null(a);

	RLC_TRY {
		fp2_new(l);
		ep_new_all(_p, d);
		bn_new(a);

		fp2_set_dig(r, 1);
		if (!ep_is_infty(p) && !(fp_is_zero(t[0]) && fp_is_zero(t[1]))) {
			/* By symmetry, P takes the place of the second argument, with the
			 * doubling lines evaluated at -P as in pp_mil_k2(). */
			ep_norm(_p, p);
			ep_neg(d, _p);
			ep_curve_get_ord(a);
			bn_sub_dig(a, a, 1);
			bn_rec_naf(b, &len, a, 2);
			for (i = len - 2; i >= 0; i--) {
				fp2_sqr(r, r);
				for (int k = 0; k < 2; k++) {
					const dig_t *x = (k == 0 ? d->x : _p->x);
					const dig_t *y = (k == 0 ? d->y : _p->y);
					if (k == 1 && b[i] == 0) {
						break;
					}
					fp_mul(l[0], t[2 * j], x);
					fp_add(l[0], l[0], t[2 * j + 1]);
					fp_copy(l[1], y);
					fp2_mul(r, r, l);
					j++;
				}
			}
			pp_exp_k2(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp2_free(l);
		ep_free_all(_p, d);
		bn_free(a);
	}
}
