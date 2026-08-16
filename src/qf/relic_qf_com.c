/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of the binary quadratic form duplication.
 *
 * @ingroup qf
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/*
 * NUCOMP, following van der Poorten's formulation as implemented in BICYCL.
 * See the long comment on QFI::nucomp there for the 2x4 matrix whose minors
 * are (a1, a2, s, m, c2, c1); the code below builds that matrix, partially
 * reduces its second column, and reads the composed form off the minors.
 */
void qf_com(qf_t r, const qf_t f, const qf_t g, int neg, const bn_t d) {
	bn_t Ax, Ay, Bx, By, by, Cx, Cy, Dx, Dy, F, H, l, m, q, m00, m01, m10, m11;
	bn_t ra, rb, rc, s, t0, t1, t2, u, v, x, y;

	bn_null(Ax);
	bn_null(Ay);
	bn_null(Bx);
	bn_null(By);
	bn_null(by);
	bn_null(Cx);
	bn_null(Cy);
	bn_null(Dx);
	bn_null(Dy);
	bn_null(F);
	bn_null(H);
	bn_null(l);
	bn_null(m);
	bn_null(q);
	bn_null(m00);
	bn_null(m01);
	bn_null(m10);
	bn_null(m11);
	bn_null(ra);
	bn_null(rb);
	bn_null(rc);
	bn_null(s);
	bn_null(t0);
	bn_null(t1);
	bn_null(t2);
	bn_null(u);
	bn_null(v);
	bn_null(x);
	bn_null(y);

	RLC_TRY {
		bn_new(Ax);
		bn_new(Ay);
		bn_new(Bx);
		bn_new(By);
		bn_new(by);
		bn_new(Cx);
		bn_new(Cy);
		bn_new(Dx);
		bn_new(Dy);
		bn_new(F);
		bn_new(H);
		bn_new(m);
		bn_new(l);
		bn_new(q);
		bn_new(m00);
		bn_new(m01);
		bn_new(m10);
		bn_new(m11);
		bn_new(ra);
		bn_new(rb);
		bn_new(rc);
		bn_new(s);
		bn_new(t0);
		bn_new(t1);
		bn_new(t2);
		bn_new(u);
		bn_new(v);
		bn_new(x);
		bn_new(y);

		/* s = (b1 + b2) / 2, m = b2 - s */
		bn_add(s, f->b, g->b);
		bn_rsh(s, s, 1);
		bn_sub(m, g->b, s);

		if (neg) {
			bn_neg(t0, m);
			bn_neg(m, s);
			bn_copy(s, t0);
		}

		/* F = gcd(a1, a2) = u*a1 + v*a2 (Lehmer: see bn_gcd_ext_signed) */
		bn_gcd_ext(F, u, v, f->a, g->a);

		if (bn_cmp_dig(F, 1) == RLC_EQ) {
			bn_set_dig(Ax, 1);
			bn_mul(Bx, m, v);
			bn_copy(By, f->a);
		} else {
			bn_mod(t0, s, F);
			if (bn_is_zero(t0)) {
				bn_copy(Ax, F);
				bn_mul(Bx, m, v);
				bn_div(By, f->a, Ax);
			} else {
				bn_gcd_ext(Ax, x, y, F, s);
				bn_div(H, F, Ax);
				bn_mod(t0, f->c, H);
				bn_mod(t1, g->c, H);
				bn_mul(t0, t0, v);
				bn_mul(t2, t1, u);
				bn_add(t0, t0, t2);
				bn_mod(t0, t0, H);
				bn_mul(t0, t0, y);
				bn_mod(l, t0, H);

				bn_div(By, f->a, Ax);

				bn_mul(t0, v, m);
				bn_mul(t2, l, By);
				bn_add(t0, t0, t2);
				bn_div(Bx, t0, H);
			}
		}
		bn_div(Cy, g->a, Ax);
		bn_div(Dy, s, Ax);

		/* Bx <- Bx mod By */
		bn_div_rem(q, t0, Bx, By);
		bn_copy(Bx, t0);

		bn_gcd_ext_par(Bx, by, m00, m01, m10, m11, Bx, By, d);

		/* Ay */
		bn_mul(Ay, m10, Ax);
		bn_neg(Ay, Ay);

		/* Cx, Cy */
		bn_mul(Cx, Bx, Cy);
		bn_mul(t0, m, m11);
		bn_sub(Cx, Cx, t0);
		bn_div(Cx, Cx, By);

		if (bn_is_zero(Bx)) {
			bn_mul(Cy, g->a, by);
			bn_mul(t0, Ay, m);
			bn_sub(Cy, Cy, t0);
			bn_div(Cy, Cy, f->a);
		} else {
			bn_mul(Cy, Cx, by);
			bn_add(Cy, Cy, m);
			bn_div(Cy, Cy, Bx);
		}

		/* Dx, Dy */
		bn_mul(Dx, Bx, Dy);
		bn_mul(t0, g->c, m11);
		bn_sub(Dx, Dx, t0);
		bn_div(Dx, Dx, By);

		bn_mul(t0, Dx, m10);
		bn_sub(Dy, Dy, t0);
		bn_div(Dy, Dy, m11);

		bn_mul(Ax, m11, Ax);

		/* a = by*Cy - Ay*Dy */
		bn_mul(ra, by, Cy);
		bn_mul(t0, Ay, Dy);
		bn_sub(ra, ra, t0);

		/* c = Bx*Cx - Ax*Dx */
		bn_mul(rc, Bx, Cx);
		bn_mul(t0, Ax, Dx);
		bn_sub(rc, rc, t0);

		/* b = (Ax*Dy + Ay*Dx) - (Bx*Cy + by*Cx) */
		bn_mul(rb, Ax, Dy);
		bn_mul(t0, Ay, Dx);
		bn_add(rb, rb, t0);
		bn_mul(t0, Bx, Cy);
		bn_sub(rb, rb, t0);
		bn_mul(t0, by, Cx);
		bn_sub(rb, rb, t0);

		bn_copy(r->a, ra);
		bn_copy(r->b, rb);
		bn_copy(r->c, rc);
		qf_rdc(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(Ax);
		bn_free(Ay);
		bn_free(Bx);
		bn_free(By);
		bn_free(by);
		bn_free(Cx);
		bn_free(Cy);
		bn_free(Dx);
		bn_free(Dy);
		bn_free(F);
		bn_free(H);
		bn_free(l);
		bn_free(m);
		bn_free(q);
		bn_free(m00);
		bn_free(m01);
		bn_free(m10);
		bn_free(m11);
		bn_free(ra);
		bn_free(rb);
		bn_free(rc);
		bn_free(s);
		bn_free(t0);
		bn_free(t1);
		bn_free(t2);
		bn_free(u);
		bn_free(v);
		bn_free(x);
		bn_free(y);
	}
}

