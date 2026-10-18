/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of the pairing for supersingular curves over Fp^4 with
 * embedding degree 3.
 *
 * The curve is E: y^2 = x^3 + v over Fq = Fp^4 = Fp^2[v]/(v^2 - xi), and the
 * pairing is the symmetric eta_d pairing with loop parameter d, where
 * p = d mod r and r = d^4 - d^2 + 1. The lines are built in the basis
 * {1, w, w^2} of Fp^12 = Fq[w]/(w^3 - v), which is the tower of Fp^12 with
 * w as its generator z, since z^6 = xi = v^2.
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
 * Number of precomputed values of the second pairing argument.
 */
#define PP_K3_PRE		7

/**
 * Number of coordinates of the running point in the Miller loop.
 */
#define PP_K3_PTS		5

/**
 * Halves an element of Fp^4.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to halve.
 */
static void pp_hlv_k3(fp4_t c, const fp4_t a) {
	for (int i = 0; i < 2; i++) {
		for (int j = 0; j < 2; j++) {
			fp_hlv(c[i][j], a[i][j]);
		}
	}
}

/**
 * Converts c0 + c1 * w + c2 * w^2, with c_k in Fq, to the tower of Fp^12,
 * where the coefficient of v in c_k multiplies z^(k + 3).
 *
 * @param[out] l			- the result.
 * @param[in] c0			- the coefficient of 1.
 * @param[in] c1			- the coefficient of w.
 * @param[in] c2			- the coefficient of w^2.
 */
static void pp_lin_k3(fp12_t l, const fp4_t c0, const fp4_t c1,
		const fp4_t c2) {
	fp2_copy(l[0][0], c0[0]);
	fp2_copy(l[1][0], c1[0]);
	fp2_copy(l[0][1], c2[0]);
	fp2_copy(l[1][1], c0[1]);
	fp2_copy(l[0][2], c1[1]);
	fp2_copy(l[1][2], c2[1]);
}

/**
 * Precomputes the values of the second pairing argument Q used by the lines,
 * which evaluate at psi([p]Q) and, already raised to p, at psi(Q). They are
 * xa, ya, B * xa^2, xa / 2 for psi([p]Q) = (xa * w^2, ya), and yb, then
 * B * xb^2 and xb / 2 times constants folding the Frobenius in, for
 * psi(Q) = (xb * w^2, yb).
 *
 * @param[out] c			- the precomputed values.
 * @param[in] q				- the second pairing argument in affine coordinates.
 */
static void pp_pre_k3(fp4_t *c, const ep4_t q) {
	ctx_t *ctx = core_get();
	fp4_t t, xb;

	fp4_null(t);
	fp4_null(xb);

	RLC_TRY {
		fp4_new(t);
		fp4_new(xb);

		/* xb = x^p * B^-((p + 1) / 3) and yb = y^p * B^-((p - 1) / 2). */
		fp4_frb(t, q->x, 1);
		fp4_mul(xb, t, ctx->ep4_ss3[0]);
		fp4_frb(t, q->y, 1);
		fp4_mul(c[4], t, ctx->ep4_ss3[1]);
		/* xa = xb^(p^2) * B^((p^2 - 1) / 3), ya = -yb^(p^2) / C2. */
		fp4_frb(t, xb, 2);
		fp4_mul(c[0], t, ctx->ep4_ss3[2]);
		fp4_frb(t, c[4], 2);
		fp4_mul(c[1], t, ctx->ep4_frb[1]);
		fp4_sqr(t, c[0]);
		fp4_mul_art(c[2], t);
		pp_hlv_k3(c[3], c[0]);
		fp4_sqr(t, xb);
		fp4_mul_art(t, t);
		fp4_mul(c[5], t, ctx->ep4_ss3[3]);
		pp_hlv_k3(t, xb);
		fp4_mul(c[6], t, ctx->ep4_ss3[4]);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(t);
		fp4_free(xb);
	}
}

/**
 * Computes the two lines of a Miller step, from the running point
 * (X, Y, Z, T = X^2, U = Z^2) and the values g, e of the doubling or addition.
 * The second line comes out already raised to p.
 *
 * @param[out] la			- the line evaluated at psi([p]Q).
 * @param[out] lb			- the line evaluated at psi(Q), raised to p.
 * @param[in] s				- the running point.
 * @param[in] g				- the value 2 * X * Z of the step.
 * @param[in] e				- the slope value of the step.
 * @param[in] c				- the precomputed values of Q.
 */
static void pp_lns_k3(fp12_t la, fp12_t lb, const fp4_t *s, const fp4_t g,
		const fp4_t e, const fp4_t *c) {
	fp4_t be, c0, c1, c2;
	dv4_t u0, u1;

	fp4_null(be);
	fp4_null(c0);
	fp4_null(c1);
	fp4_null(c2);
	dv4_null(u0);
	dv4_null(u1);

	RLC_TRY {
		fp4_new(be);
		fp4_new(c0);
		fp4_new(c1);
		fp4_new(c2);
		dv4_new(u0);
		dv4_new(u1);

		/* alpha = e * Y + T and beta = e * Z are shared by both lines, and
		 * alpha - beta * y is reduced once, keeping e * Y unreduced. */
		fp4_mul_unr(u0, e, s[1]);
		fp4_mul(be, e, s[2]);

		fp4_mul_unr(u1, be, c[1]);
		fp2_subc_low(u1[0], u0[0], u1[0]);
		fp2_subc_low(u1[1], u0[1], u1[1]);
		fp2_rdcn_low(c0[0], u1[0]);
		fp2_rdcn_low(c0[1], u1[1]);
		fp4_add(c0, c0, s[3]);
		fp4_mul(c1, s[4], c[2]);
		fp4_mul(c2, g, c[3]);
		pp_lin_k3(la, c0, c1, c2);

		fp4_mul_unr(u1, be, c[4]);
		fp2_subc_low(u1[0], u0[0], u1[0]);
		fp2_subc_low(u1[1], u0[1], u1[1]);
		fp2_rdcn_low(c0[0], u1[0]);
		fp2_rdcn_low(c0[1], u1[1]);
		fp4_add(c0, c0, s[3]);
		fp4_mul(c1, s[4], c[5]);
		fp4_mul(c2, g, c[6]);
		/* The Frobenius maps w to w^2 and w^2 to w, up to constants that
		 * were folded into the precomputed values. */
		fp4_frb(c0, c0, 1);
		fp4_frb(c1, c1, 1);
		fp4_frb(c2, c2, 1);
		pp_lin_k3(lb, c0, c2, c1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(be);
		fp4_free(c0);
		fp4_free(c1);
		fp4_free(c2);
		dv4_free(u0);
		dv4_free(u1);
	}
}

/**
 * Doubles the running point (X, Y, Z, T = X^2, U = Z^2) of the Miller loop,
 * returning the values g = 2 * X3 * Z3 and e = 3 * (2 * X * Y)^2 for the lines.
 *
 * @param[in,out] s			- the running point.
 * @param[out] g			- the value 2 * X3 * Z3.
 * @param[out] e			- the slope value.
 */
static void pp_dbl_k3(fp4_t *s, fp4_t g, fp4_t e) {
	fp4_t a, b, c, d;

	fp4_null(a);
	fp4_null(b);
	fp4_null(c);
	fp4_null(d);

	RLC_TRY {
		fp4_new(a);
		fp4_new(b);
		fp4_new(c);
		fp4_new(d);

		/* A = Y^2, B = 2 * X * Y, C = 2 * Y * Z, D = 3 * b * Z^2. */
		fp4_sqr(a, s[1]);
		fp4_add(b, s[0], s[1]);
		fp4_sqr(b, b);
		fp4_sub(b, b, s[3]);
		fp4_sub(b, b, a);
		fp4_add(c, s[1], s[2]);
		fp4_sqr(c, c);
		fp4_sub(c, c, a);
		fp4_sub(c, c, s[4]);
		fp4_mul_art(d, s[4]);
		fp4_mul_dig(d, d, 3);
		/* X3 = B * (A - 3 * D). */
		fp4_mul_dig(e, d, 3);
		fp4_sub(g, a, e);
		fp4_mul(s[0], b, g);
		/* Y3 = (A + 3 * D)^2 - 12 * D^2. */
		fp4_add(g, a, e);
		fp4_sqr(s[1], g);
		fp4_sqr(d, d);
		fp4_mul_dig(d, d, 12);
		fp4_sub(s[1], s[1], d);
		/* Z3 = 4 * A * C. */
		fp4_mul(s[2], a, c);
		fp4_dbl(s[2], s[2]);
		fp4_dbl(s[2], s[2]);
		fp4_sqr(s[3], s[0]);
		fp4_sqr(s[4], s[2]);
		fp4_add(g, s[0], s[2]);
		fp4_sqr(g, g);
		fp4_sub(g, g, s[3]);
		fp4_sub(g, g, s[4]);
		fp4_sqr(e, b);
		fp4_mul_dig(e, e, 3);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(a);
		fp4_free(b);
		fp4_free(c);
		fp4_free(d);
	}
}

/**
 * Adds an affine point P to the running point (X, Y, Z, T = X^2, U = Z^2) of
 * the Miller loop, returning the values g = 2 * X3 * Z3 and e for the lines.
 *
 * @param[in,out] s			- the running point.
 * @param[out] g			- the value 2 * X3 * Z3.
 * @param[out] e			- the slope value.
 * @param[in] p				- the point to add, in affine coordinates.
 */
static void pp_add_k3(fp4_t *s, fp4_t g, fp4_t e, const ep4_t p) {
	fp4_t a, b, c, d, f, h;
	dv4_t u0, u1;

	fp4_null(a);
	fp4_null(b);
	fp4_null(c);
	fp4_null(d);
	fp4_null(f);
	fp4_null(h);
	dv4_null(u0);
	dv4_null(u1);

	RLC_TRY {
		fp4_new(a);
		fp4_new(b);
		fp4_new(c);
		fp4_new(d);
		fp4_new(f);
		fp4_new(h);
		dv4_new(u0);
		dv4_new(u1);

		/* A = X - Z * x2, B = A^2, C = A * B, D = X * B. */
		fp4_mul(a, s[2], p->x);
		fp4_sub(a, s[0], a);
		fp4_sqr(b, a);
		fp4_mul(c, a, b);
		fp4_mul(d, s[0], b);
		/* E = 2 * D - C and F = D + E. */
		fp4_dbl(e, d);
		fp4_sub(e, e, c);
		fp4_add(f, d, e);
		/* G = Y - Z * y2, H = G * Z and I = G * H. */
		fp4_mul(g, s[2], p->y);
		fp4_sub(g, s[1], g);
		fp4_mul(h, g, s[2]);
		fp4_mul(d, g, h);
		/* X3 = A * (I - E), Y3 = G * (F - I) - Y * C and Z3 = Z * C. */
		fp4_sub(e, d, e);
		fp4_mul(s[0], a, e);
		fp4_sub(f, f, d);
		fp4_mul_unr(u0, g, f);
		fp4_mul_unr(u1, s[1], c);
		fp2_subc_low(u0[0], u0[0], u1[0]);
		fp2_subc_low(u0[1], u0[1], u1[1]);
		fp2_rdcn_low(s[1][0], u0[0]);
		fp2_rdcn_low(s[1][1], u0[1]);
		fp4_mul(s[2], s[2], c);
		fp4_sqr(s[3], s[0]);
		fp4_sqr(s[4], s[2]);
		fp4_add(g, s[0], s[2]);
		fp4_sqr(g, g);
		fp4_sub(g, g, s[3]);
		fp4_sub(g, g, s[4]);
		/* The slope value is H * B. */
		fp4_mul(e, h, b);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(a);
		fp4_free(b);
		fp4_free(c);
		fp4_free(d);
		fp4_free(f);
		fp4_free(h);
		dv4_free(u0);
		dv4_free(u1);
	}
}

/**
 * Computes the inverses of the vertical line at P, evaluated at psi([p]Q) and,
 * raised to p, at psi(Q), needed by negative digits of the loop parameter. For
 * psi(Q) = (x * w^2, y), the inverse of x * w^2 - xP is xP^2 + B * x^2 * w +
 * xP * x * w^2 up to a factor in Fq, which the final exponentiation removes.
 *
 * @param[out] na			- the inverse at psi([p]Q).
 * @param[out] nb			- the inverse at psi(Q), raised to p.
 * @param[in] p				- the first pairing argument in affine coordinates.
 * @param[in] c				- the precomputed values of Q.
 */
static void pp_ver_k3(fp12_t na, fp12_t nb, const ep4_t p, const fp4_t *c) {
	fp4_t c0, c1, c2;

	fp4_null(c0);
	fp4_null(c1);
	fp4_null(c2);

	RLC_TRY {
		fp4_new(c0);
		fp4_new(c1);
		fp4_new(c2);

		fp4_sqr(c0, p->x);
		fp4_mul(c2, p->x, c[0]);
		pp_lin_k3(na, c0, c[2], c2);

		/* The precomputed values of psi(Q) fold in the Frobenius. */
		fp4_mul(c2, p->x, c[6]);
		fp4_dbl(c2, c2);
		fp4_frb(c0, c0, 1);
		fp4_frb(c1, c[5], 1);
		fp4_frb(c2, c2, 1);
		pp_lin_k3(nb, c0, c2, c1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(c0);
		fp4_free(c1);
		fp4_free(c2);
	}
}

/**
 * Computes the final line of the pairing, through P and -[p^2]P, evaluated at
 * psi([p]Q). The denominator lies in Fq and is dropped.
 *
 * @param[out] l			- the line.
 * @param[in] p				- the first pairing argument in affine coordinates.
 * @param[in] c				- the precomputed values of Q.
 */
static void pp_fin_k3(fp12_t l, const ep4_t p, const fp4_t *c) {
	ctx_t *ctx = core_get();
	fp4_t x1, y1, b0, b1, s, t;

	fp4_null(x1);
	fp4_null(y1);
	fp4_null(b0);
	fp4_null(b1);
	fp4_null(s);
	fp4_null(t);

	RLC_TRY {
		fp4_new(x1);
		fp4_new(y1);
		fp4_new(b0);
		fp4_new(b1);
		fp4_new(s);
		fp4_new(t);

		/* -[p^2]P = (x / N3, -y / N2). */
		fp4_mul(x1, p->x, ctx->ep4_ss3[5]);
		fp4_mul(y1, p->y, ctx->ep4_ss3[6]);
		/* b1 = yP - y1, S = (ya - y1) * (xP - x1), b0 = S + x1 * b1. */
		fp4_sub(b1, p->y, y1);
		fp4_sub(s, c[1], y1);
		fp4_sub(t, p->x, x1);
		fp4_mul(s, s, t);
		fp4_mul(b0, x1, b1);
		fp4_add(b0, b0, s);
		/* l2 = b0 * S * xa and l1 = b1 * S * B * xa^2. */
		fp4_mul(t, b0, s);
		fp4_mul(y1, t, c[0]);
		fp4_mul(t, b1, s);
		fp4_mul(s, t, c[2]);
		/* l0 = b1^2 * B^2 * xa^3 - b0^2 * x1. */
		fp4_sqr(t, c[0]);
		fp4_mul(t, t, c[0]);
		fp4_mul_art(t, t);
		fp4_mul_art(t, t);
		fp4_sqr(b1, b1);
		fp4_mul(t, t, b1);
		fp4_sqr(b0, b0);
		fp4_mul(b0, b0, x1);
		fp4_sub(t, t, b0);
		pp_lin_k3(l, t, s, y1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free(x1);
		fp4_free(y1);
		fp4_free(b0);
		fp4_free(b1);
		fp4_free(s);
		fp4_free(t);
	}
}

/**
 * Computes the Miller loop of the eta_d pairing for m pairs of arguments,
 * including the final line, sharing a single accumulator.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first pairing arguments, in affine form.
 * @param[in] q				- the second pairing arguments, in affine form.
 * @param[in] m				- the number of pairs.
 */
static void pp_mil_k3(fp12_t r, const ep4_t *p, const ep4_t *q, int m) {
	fp4_t *s = RLC_ALLOCA(fp4_t, PP_K3_PTS * m);
	fp4_t *c = RLC_ALLOCA(fp4_t, PP_K3_PRE * m);
	ep4_t *n = RLC_ALLOCA(ep4_t, m);
	fp12_t la, lb;
	fp4_t g, e;
	bn_t d;
	int i, j, k, first = 1;
	size_t len = RLC_FP_BITS + 1;
	int8_t naf[RLC_FP_BITS + 1];

	fp12_null(la);
	fp12_null(lb);
	fp4_null(g);
	fp4_null(e);
	bn_null(d);

	if (s == NULL || c == NULL || n == NULL) {
		RLC_FREE(s);
		RLC_FREE(c);
		RLC_FREE(n);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (j = 0; j < PP_K3_PTS * m; j++) {
		fp4_null(s[j]);
	}
	for (j = 0; j < PP_K3_PRE * m; j++) {
		fp4_null(c[j]);
	}
	for (j = 0; j < m; j++) {
		ep4_null(n[j]);
	}

	RLC_TRY {
		fp12_new(la);
		fp12_new(lb);
		fp4_new(g);
		fp4_new(e);
		bn_new(d);
		for (j = 0; j < PP_K3_PTS * m; j++) {
			fp4_new(s[j]);
		}
		for (j = 0; j < PP_K3_PRE * m; j++) {
			fp4_new(c[j]);
		}
		for (j = 0; j < m; j++) {
			ep4_new(n[j]);
			ep4_neg(n[j], p[j]);
		}

		for (j = 0; j < m; j++) {
			pp_pre_k3(c + PP_K3_PRE * j, q[j]);
			k = PP_K3_PTS * j;
			fp4_copy(s[k], p[j]->x);
			fp4_copy(s[k + 1], p[j]->y);
			fp4_set_dig(s[k + 2], 1);
			fp4_sqr(s[k + 3], p[j]->x);
			fp4_set_dig(s[k + 4], 1);
		}

		fp_prime_get_par(d);
		bn_rec_naf(naf, &len, d, 2);
		fp12_set_dig(r, 1);
		for (i = len - 2; i >= 0; i--) {
			if (!first) {
				fp12_sqr(r, r);
			}
			for (j = 0; j < m; j++) {
				pp_dbl_k3(s + PP_K3_PTS * j, g, e);
				pp_lns_k3(la, lb, s + PP_K3_PTS * j, g, e,
						c + PP_K3_PRE * j);
				if (first) {
					fp12_copy(r, la);
					first = 0;
				} else {
					fp12_mul(r, r, la);
				}
				fp12_mul(r, r, lb);
			}
			if (naf[i] != 0) {
				for (j = 0; j < m; j++) {
					pp_add_k3(s + PP_K3_PTS * j, g, e,
							(naf[i] > 0 ? p[j] : n[j]));
					pp_lns_k3(la, lb, s + PP_K3_PTS * j, g, e,
							c + PP_K3_PRE * j);
					fp12_mul(r, r, la);
					fp12_mul(r, r, lb);
					if (naf[i] < 0) {
						/* Odd embedding degree: verticals do not vanish. */
						pp_ver_k3(la, lb, p[j], c + PP_K3_PRE * j);
						fp12_mul(r, r, la);
						fp12_mul(r, r, lb);
					}
				}
			}
		}
		/* A single accumulator suffices since A^(p^2) * B^p = (A^p * B)^p. */
		fp12_frb(r, r, 1);

		for (j = 0; j < m; j++) {
			pp_fin_k3(la, p[j], c + PP_K3_PRE * j);
			fp12_mul(r, r, la);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp12_free(la);
		fp12_free(lb);
		fp4_free(g);
		fp4_free(e);
		bn_free(d);
		for (j = 0; j < PP_K3_PTS * m; j++) {
			fp4_free(s[j]);
		}
		for (j = 0; j < PP_K3_PRE * m; j++) {
			fp4_free(c[j]);
		}
		for (j = 0; j < m; j++) {
			ep4_free(n[j]);
		}
		RLC_FREE(s);
		RLC_FREE(c);
		RLC_FREE(n);
	}
}

/**
 * Evaluates the two lines of a Miller step from the values of a table built by
 * pp_map_pre_k3(), as pp_lns_k3() does from the running point: with the lines
 * divided by beta = e * Z, which the final exponentiation removes, they only
 * need (e * Y + T) / beta, U / beta and g / beta.
 *
 * @param[out] la			- the line evaluated at psi([p]P).
 * @param[out] lb			- the line evaluated at psi(P), raised to p.
 * @param[in] t				- the three values of the step.
 * @param[in] c				- the precomputed values of P.
 */
static void pp_lfx_k3(fp12_t la, fp12_t lb, const fp4_t *t, const fp4_t *c) {
	fp4_t c0, c1, c2;

	fp4_null_all(c0, c1, c2);

	RLC_TRY {
		fp4_new_all(c0, c1, c2);

		fp4_sub(c0, t[0], c[1]);
		fp4_mul(c1, t[1], c[2]);
		fp4_mul(c2, t[2], c[3]);
		pp_lin_k3(la, c0, c1, c2);

		fp4_sub(c0, t[0], c[4]);
		fp4_mul(c1, t[1], c[5]);
		fp4_mul(c2, t[2], c[6]);
		fp4_frb(c0, c0, 1);
		fp4_frb(c1, c1, 1);
		fp4_frb(c2, c2, 1);
		pp_lin_k3(lb, c0, c2, c1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp4_free_all(c0, c1, c2);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pp_map_oatep_k3(fp12_t r, const ep4_t p, const ep4_t q) {
	ep4_t _p[1], _q[1];

	ep4_null(_p[0]);
	ep4_null(_q[0]);

	RLC_TRY {
		ep4_new(_p[0]);
		ep4_new(_q[0]);

		fp12_set_dig(r, 1);
		if (!ep4_is_infty(p) && !ep4_is_infty(q)) {
			ep4_norm(_p[0], p);
			ep4_norm(_q[0], q);
			pp_mil_k3(r, (const ep4_t *)_p, (const ep4_t *)_q, 1);
			pp_exp_k3(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep4_free(_p[0]);
		ep4_free(_q[0]);
	}
}

void pp_map_sim_oatep_k3(fp12_t r, const ep4_t *p, const ep4_t *q, int m) {
	ep4_t *_p = RLC_ALLOCA(ep4_t, m), *_q = RLC_ALLOCA(ep4_t, m);
	int i, j;

	if (_p == NULL || _q == NULL) {
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (i = 0; i < m; i++) {
		ep4_null(_p[i]);
		ep4_null(_q[i]);
	}

	RLC_TRY {
		for (i = 0; i < m; i++) {
			ep4_new(_p[i]);
			ep4_new(_q[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep4_is_infty(p[i]) && !ep4_is_infty(q[i])) {
				ep4_norm(_p[j], p[i]);
				ep4_norm(_q[j++], q[i]);
			}
		}

		fp12_set_dig(r, 1);
		if (j > 0) {
			pp_mil_k3(r, (const ep4_t *)_p, (const ep4_t *)_q, j);
			pp_exp_k3(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < m; i++) {
			ep4_free(_p[i]);
			ep4_free(_q[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
	}
}

void pp_map_pre_k3(fp4_t *t, const ep4_t q) {
	fp4_t *y = RLC_ALLOCA(fp4_t, RLC_PP_TABLE_K3 / 3);
	fp4_t s[PP_K3_PTS], g, e, u;
	ep4_t _q, n;
	bn_t d;
	int i, j = 0;
	size_t len = RLC_FP_BITS + 1;
	int8_t naf[RLC_FP_BITS + 1];

	if (y == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (i = 0; i < PP_K3_PTS; i++) {
		fp4_null(s[i]);
	}
	for (i = 0; i < RLC_PP_TABLE_K3 / 3; i++) {
		fp4_null(y[i]);
	}
	fp4_null_all(g, e, u);
	ep4_null_all(_q, n);
	bn_null(d);

	RLC_TRY {
		for (i = 0; i < PP_K3_PTS; i++) {
			fp4_new(s[i]);
		}
		for (i = 0; i < RLC_PP_TABLE_K3 / 3; i++) {
			fp4_new(y[i]);
		}
		fp4_new_all(g, e, u);
		ep4_new_all(_q, n);
		bn_new(d);

		/* A table with Q at zero stands for the point at infinity. */
		fp4_zero(t[0]);
		fp4_zero(t[1]);
		if (!ep4_is_infty(q)) {
			/* The pairing is symmetric, so the loop runs over Q instead. */
			ep4_norm(_q, q);
			ep4_neg(n, _q);
			fp4_copy(t[0], _q->x);
			fp4_copy(t[1], _q->y);
			fp4_copy(s[0], _q->x);
			fp4_copy(s[1], _q->y);
			fp4_set_dig(s[2], 1);
			fp4_sqr(s[3], _q->x);
			fp4_set_dig(s[4], 1);

			fp_prime_get_par(d);
			bn_rec_naf(naf, &len, d, 2);
			for (i = len - 2; i >= 0; i--) {
				for (int k = 0; k < 2; k++) {
					if (k == 0) {
						pp_dbl_k3(s, g, e);
					} else if (naf[i] != 0) {
						pp_add_k3(s, g, e, naf[i] > 0 ? _q : n);
					} else {
						break;
					}
					if (3 * j + 5 > RLC_PP_TABLE_K3) {
						RLC_THROW(ERR_NO_BUFFER);
						break;
					}
					/* Store e * Y + T, U and g, and keep beta = e * Z. */
					fp4_mul(u, e, s[1]);
					fp4_add(t[3 * j + 2], u, s[3]);
					fp4_copy(t[3 * j + 3], s[4]);
					fp4_copy(t[3 * j + 4], g);
					fp4_mul(y[j], e, s[2]);
					j++;
				}
			}

			/* Divide the values of each step by its beta. */
			fp4_inv_sim(y, (const fp4_t *)y, j);
			for (i = 0; i < j; i++) {
				for (int k = 2; k < 5; k++) {
					fp4_mul(t[3 * i + k], t[3 * i + k], y[i]);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < PP_K3_PTS; i++) {
			fp4_free(s[i]);
		}
		for (i = 0; i < RLC_PP_TABLE_K3 / 3; i++) {
			fp4_free(y[i]);
		}
		fp4_free_all(g, e, u);
		ep4_free_all(_q, n);
		bn_free(d);
		RLC_FREE(y);
	}
}

void pp_map_fix_k3(fp12_t r, const ep4_t p, const fp4_t *t) {
	fp4_t c[PP_K3_PRE];
	fp12_t la, lb;
	ep4_t _p, q;
	bn_t d;
	int i, j = 0;
	size_t len = RLC_FP_BITS + 1;
	int8_t naf[RLC_FP_BITS + 1];

	for (i = 0; i < PP_K3_PRE; i++) {
		fp4_null(c[i]);
	}
	fp12_null_all(la, lb);
	ep4_null_all(_p, q);
	bn_null(d);

	RLC_TRY {
		for (i = 0; i < PP_K3_PRE; i++) {
			fp4_new(c[i]);
		}
		fp12_new_all(la, lb);
		ep4_new_all(_p, q);
		bn_new(d);

		fp12_set_dig(r, 1);
		if (!ep4_is_infty(p) && !(fp4_is_zero(t[0]) && fp4_is_zero(t[1]))) {
			/* By symmetry, P takes the place of the second argument. */
			ep4_norm(_p, p);
			pp_pre_k3(c, _p);
			fp4_copy(q->x, t[0]);
			fp4_copy(q->y, t[1]);
			fp4_set_dig(q->z, 1);
			q->coord = EC_AFFIN;

			fp_prime_get_par(d);
			bn_rec_naf(naf, &len, d, 2);
			for (i = len - 2; i >= 0; i--) {
				pp_lfx_k3(la, lb, t + 3 * j + 2, (const fp4_t *)c);
				if (j++ == 0) {
					fp12_copy(r, la);
				} else {
					fp12_sqr(r, r);
					fp12_mul(r, r, la);
				}
				fp12_mul(r, r, lb);
				if (naf[i] != 0) {
					pp_lfx_k3(la, lb, t + 3 * j++ + 2, (const fp4_t *)c);
					fp12_mul(r, r, la);
					fp12_mul(r, r, lb);
					if (naf[i] < 0) {
						pp_ver_k3(la, lb, q, (const fp4_t *)c);
						fp12_mul(r, r, la);
						fp12_mul(r, r, lb);
					}
				}
			}
			fp12_frb(r, r, 1);
			pp_fin_k3(la, q, (const fp4_t *)c);
			fp12_mul(r, r, la);
			pp_exp_k3(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < PP_K3_PRE; i++) {
			fp4_free(c[i]);
		}
		fp12_free_all(la, lb);
		ep4_free_all(_p, q);
		bn_free(d);
	}
}
