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
 * degree 1.
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
 * @param[in] n 			- the number of pairings to evaluate.
 * @param[in] a				- the loop parameter.
 */
static void pp_mil_k1(fp_t r, ep_t *t, ep_t *p, ep_t *q, int n, bn_t a) {
	fp_t l, m, s, *w = RLC_ALLOCA(fp_t, n);
	int i, j;
	size_t len = bn_bits(a) + 1;
	int8_t b[RLC_FP_BITS + 1];

	if (w == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	fp_null(l);
	fp_null(m);
	fp_null(s);
	for (j = 0; j < n; j++) {
		fp_null(w[j]);
	}

	RLC_TRY {
		fp_new(l);
		fp_new(m);
		fp_new(s);
		for (j = 0; j < n; j++) {
			fp_new(w[j]);
			ep_copy(t[j], p[j]);
			fp_set_dig(w[j], 1);
		}

		fp_set_dig(s, 1);
		bn_rec_naf(b, &len, a, 2);
		for (i = len - 2; i >= 0; i--) {
			fp_sqr(r, r);
			fp_sqr(s, s);
			for (j = 0; j < n; j++) {
				pp_dbl_k1(l, m, t[j], w[j], t[j], w[j], q[j]);
				fp_mul(r, r, l);
				fp_mul(s, s, m);
				if (b[i] > 0) {
					pp_add_k1(l, m, t[j], p[j], q[j]);
					/* Correct extended coordinate for next doubling. */
					fp_sqr(w[j], t[j]->z);
					fp_mul(r, r, l);
					fp_mul(s, s, m);
				}
				if (b[i] < 0) {
					ep_neg(p[j], p[j]);
					pp_add_k1(l, m, t[j], p[j], q[j]);
					ep_neg(p[j], p[j]);
					/* Correct extended coordinate for next doubling. */
					fp_sqr(w[j], t[j]->z);
					fp_mul(r, r, l);
					fp_mul(s, s, m);
					/* Since f_{-1} = 1/v_P, subtracting P also divides by the
					 * vertical line through P, which matters for k = 1. */
					fp_sub(l, q[j]->x, p[j]->x);
					fp_mul(s, s, l);
				}
			}
		}

		if (!fp_is_zero(s)) {
			fp_inv(s, s);
			fp_mul(r, r, s);
		} else {
			fp_set_dig(r, 1);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(l);
		fp_free(m);
		fp_free(s);
		for (j = 0; j < n; j++) {
			fp_free(w[j]);
		}
		RLC_FREE(w);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_add_k1_basic(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q) {
	fp_t s;

	fp_null(s);

	RLC_TRY {
		fp_new(s);

		if (fp_cmp(r->x, p->x) == RLC_EQ) {
			fp_set_dig(m, 1);
			fp_sub(l, q->x, p->x);
		} else {
			fp_sub(l, q->x, p->x);
			ep_add_slp_basic(r, s, r, p);
			fp_mul(l, l, s);
			fp_sub(l, q->y, l);
			fp_sub(l, l, p->y);
			if (fp_is_zero(l)) {
				fp_set_dig(l, 1);
			}
			fp_sub(m, q->x, r->x);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(s);
	}
}

void pp_add_k1_projc(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q) {
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

		fp_sqr(l, r->z);
		fp_mul(l, l, p->x);
		if (fp_cmp(l, r->x) == RLC_EQ) {
			fp_set_dig(m, 1);
			fp_sub(l, q->x, p->x);
		} else {
			/* t0 = z1^2. */
			fp_sqr(t0, r->z);

			/* t3 = U = x2 * z1^2. */
			fp_mul(t3, p->x, t0);

			/* t1 = S = y2 * z1^3. */
			fp_mul(t1, t0, r->z);
			fp_mul(t1, t1, p->y);

			/* t2 = H = U - x1. */
			fp_sub(t2, t3, r->x);

			/* t4 = L = S - y1. */
			fp_sub(t4, t1, r->y);

			/* t5 = H_2 = 2H, t3 = I = 4H^2. */
			fp_dbl(t5, t2);
			fp_sqr(t3, t5);

			/* Z3 = (Z1 + H)^2 - Z1^2 - H^2 = 2 * z1 * H. */
			fp_mul(r->z, r->z, t5);

			/* t4 = M = 2L, t5 = M3 = (L + Z3)^2 - L^2 - Z3^2 = 2 * L * Z3. */
			fp_dbl(t4, t4);
			fp_mul(t5, t4, r->z);

			/* l = Z3^2 * (yQ - y2) - M3*(xQ - x2). */
			fp_sqr(m, r->z);
			fp_sub(l, q->y, p->y);
			fp_mul(l, l, m);
			fp_sub(t0, q->x, p->x);
			fp_mul(t0, t0, t5);
			fp_sub(l, l, t0);
			if (fp_is_zero(l)) {
				fp_set_dig(l, 1);
			}

			/* t0 = V = x1 * I, t3 = J = HI, x3 = 4L^2 - J - 2V*/
			fp_mul(t0, r->x, t3);
			fp_mul(t3, t3, t2);
			fp_sqr(r->x, t4);
			fp_sub(r->x, r->x, t3);
			fp_sub(r->x, r->x, t0);
			fp_sub(r->x, r->x, t0);

			/* y3 = M * (V - X3) - 2y1 * J. */
			fp_mul(r->y, r->y, t3);
			fp_dbl(r->y, r->y);
			fp_sub(t0, t0, r->x);
			fp_mul(t0, t4, t0);
			fp_sub(r->y, t0, r->y);

			/* v = Z3^2 * xQ - X3. */
			fp_mul(m, m, q->x);
			fp_sub(m, m, r->x);

			r->coord = JACOB;
		}
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

/* Formulas from "Generation and Tate Pairing Computation
 * of Ordinary Elliptic Curves with Embedding Degree One", by Hu et al. */

void pp_dbl_k1_basic(fp_t l, fp_t m, ep_t r, const ep_t p, const ep_t q) {
	fp_t s;

	fp_null(s);

	RLC_TRY {
		fp_new(s);

		ep_dbl_slp_basic(r, s, p);
		fp_sub(m, q->x, r->x);
		fp_mul(l, m, s);
		fp_sub(l, r->y, l);
		fp_add(l, l, q->y);
		if (fp_is_zero(l)) {
			fp_set_dig(l, 1);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(s);
	}
}

void pp_dbl_k1_projc(fp_t l, fp_t m, ep_t r, fp_t w, const ep_t p, const fp_t v,
		const ep_t q) {
	fp_t t0, t1, t2, t3, t4;

	fp_null(t0);
	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);

	RLC_TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);

		/* dbl-2007-bl formulas 1M + 8S + 1*a + 10add + 2*2 + 1*3 + 1*8 */
		/* with the extended coordinate optimization w = z^2 applied.  */

		/* t0 = y1^2. */
		fp_sqr(t0, p->y);

		/* t1 = x1^2. */
		fp_sqr(t1, p->x);

		/* t2 = y1^4.*/
		fp_sqr(t2, t0);

		/* t3 = S = 2*((X1+YY)^2-XX-YYYY). */
		fp_add(t3, p->x, t0);
		fp_sqr(t3, t3);
		fp_sub(t3, t3, t1);
		fp_sub(t3, t3, t2);
		fp_dbl(t3, t3);

		/* z3 = (Y1+Z1)^2-YY-ZZ, */
		fp_add(r->z, p->y, p->z);
		fp_sqr(r->z, r->z);
		fp_sub(r->z, r->z, t0);
		fp_sub(r->z, r->z, v);

		/* t4 = M = 3*XX+a*ZZ^2. */
		fp_dbl(t4, t1);
		fp_add(t4, t4, t1);
		fp_sqr(t1, v);
		ep_curve_mul_a(t0, t1);
		fp_add(t4, t4, t0);

		/* x3 = T = M^2 - 2S. */
		fp_sqr(r->x, t4);
		fp_sub(r->x, r->x, t3);
		fp_sub(r->x, r->x, t3);

		/* y3 = M*(S-T)-8*YYYY. */
		fp_sub(t0, t3, r->x);
		fp_mul(t0, t4, t0);
		fp_dbl(t2, t2);
		fp_dbl(t2, t2);
		fp_dbl(t2, t2);
		fp_sub(r->y, t0, t2);

		/* l = z3*z3^2*yQ + y3 − t4*(z3^2*xQ - x3), v = z3*(z3^2*xQ - x3)). */
		fp_sqr(w, r->z);
		fp_mul(l, r->z, w);
		fp_mul(l, l, q->y);
		fp_add(l, l, r->y);
		fp_mul(t1, w, q->x);
		fp_sub(t1, t1, r->x);
		fp_mul(m, r->z, t1);
		fp_mul(t1, t1, t4);
		fp_sub(l, l, t1);
		if (fp_is_zero(l)) {
			fp_set_dig(l, 1);
		}

		r->coord = JACOB;
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
	}
}

void pp_norm_k1(ep_t r, const ep_t p) {
	ep_norm(r, p);
}

void pp_map_tatep_k1(fp_t r, const ep_t p, const ep_t q) {
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
		/* Evaluate at Q + psi(P), which keeps the value because the pairing of
		 * P and psi(P) is trivial, but stays off the lines through multiples
		 * of P when Q is one of them. */
		ep_psi(_q[0], p);
		ep_add(_q[0], _q[0], q);
		ep_norm(_q[0], _q[0]);
		ep_curve_get_ord(n);
		fp_set_dig(r, 1);

		if (!ep_is_infty(p) && !ep_is_infty(q)) {
			pp_mil_k1(r, t, _p, _q, 1, n);
			pp_exp_k1(r, r);
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

void pp_map_sim_tatep_k1(fp_t r, const ep_t *p, const ep_t *q, int m) {
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
				/* Evaluate at Q + psi(P), as in the single pairing. */
				ep_psi(_q[j], p[i]);
				ep_add(_q[j], _q[j], q[i]);
				ep_norm(_q[j], _q[j]);
				j++;
			}
		}

		ep_curve_get_ord(n);
		fp_set_dig(r, 1);
		if (j > 0) {
			pp_mil_k1(r, t, _p, _q, j, n);
			pp_exp_k1(r, r);
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

void pp_map_weilp_k1(fp_t r, const ep_t p, const ep_t q) {
	ep_t _p[1], _q[1], t0[1], t1[1];
	fp_t r0, r1;
	bn_t n;

	ep_null(_p[0]);
	ep_null(_q[0]);
	ep_null(t0[0]);
	ep_null(t1[0]);
	fp_null(r0);
	fp_null(r1);
	bn_null(n);

	RLC_TRY {
		ep_new(_p[0]);
		ep_new(_q[0]);
		ep_new(t0[0]);
		ep_new(t1[0]);
		fp_new(r0);
		fp_new(r1);
		bn_new(n);

		ep_norm(_p[0], p);
		ep_norm(_q[0], q);
		/* The Weil pairing is trivial on a cyclic group, so apply the
		 * distortion map to make self-pairings non-trivial. */
		ep_psi(_q[0], _q[0]);
		ep_curve_get_ord(n);
		fp_set_dig(r, 1);

		if (!ep_is_infty(_p[0]) && !ep_is_infty(_q[0])) {
			fp_set_dig(r0, 1);
			fp_set_dig(r1, 1);	
			pp_mil_k1(r0, t0, _p, _q, 1, n);
			pp_mil_k1(r1, t1, _q, _p, 1, n);
			/* Compute r = (-1)^n * r0/r1. */
			fp_inv(r1, r1);
			fp_mul(r, r0, r1);
			if (!bn_is_even(n)) {
				fp_neg(r, r);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep_free(_q[0]);
		ep_free(t0[0]);
		ep_free(t1[0]);
		fp_free(r0);
		fp_free(r1);
		bn_free(n);
	}
}

void pp_map_sim_weilp_k1(fp_t r, const ep_t *p, const ep_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m),
			*_q = RLC_ALLOCA(ep_t, m),
			*t0 = RLC_ALLOCA(ep_t, m), *t1 = RLC_ALLOCA(ep_t, m);
	fp_t r0, r1;
	bn_t n;
	int i, j;

	fp_null(r0);
	fp_null(r1);
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
		fp_new(r0);
		fp_new(r1);
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
				ep_norm(_q[j], q[i]);
				ep_psi(_q[j], _q[j]);
				j++;
			}
		}

		ep_curve_get_ord(n);
		fp_set_dig(r, 1);

		if (j > 0) {
			fp_set_dig(r0, 1);
			fp_set_dig(r1, 1);	
			pp_mil_k1(r0, t0, _p, _q, j, n);
			pp_mil_k1(r1, t1, _q, _p, j, n);
			fp_inv(r1, r1);
			fp_mul(r, r0, r1);
			if (!bn_is_even(n) && (j & 1)) {
				fp_neg(r, r);
			}	
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp_free(r0);
		fp_free(r1);
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
