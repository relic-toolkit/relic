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
 * Implementation of the binary quadratic form composition.
 *
 * @ingroup qf
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/*
 * NUCOMP, following van der Poorten's formulation as implemented in BICYCL.
 */
void qf_com(qf_t r, const qf_t f, const qf_t g, int neg, const bn_t bnd) {
	bn_t Ax, Ay, Bx, By, by, Cx, Cy, Dx, Dy;
	bn_t F, H, m;
	bn_t m00, m01, m10, m11;
	bn_t s, t0, t1, u, v;

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
	bn_null(m);
	bn_null(m00);
	bn_null(m01);
	bn_null(m10);
	bn_null(m11);
	bn_null(s);
	bn_null(t0);
	bn_null(t1);
	bn_null(u);
	bn_null(v);

	/*
	 * Composing with the principal form (1, b, c) is a copy: the general path
	 * below spends a full NUCOMP and reduction on it. Reduced forms with
	 * a = 1 have b in {0, 1}, so this test is exact for reduced inputs.
	 */
	if (bn_cmp_dig(f->a, 1) == RLC_EQ && f->b->sign == RLC_POS &&
			bn_cmp_dig(f->b, 1) != RLC_GT) {
		if (neg) {
			qf_neg(r, g);
		} else {
			qf_copy(r, g);
		}
		qf_rdc(r, r);
		return;
	}
	if (bn_cmp_dig(g->a, 1) == RLC_EQ && g->b->sign == RLC_POS &&
			bn_cmp_dig(g->b, 1) != RLC_GT) {
		qf_copy(r, f);
		qf_rdc(r, r);
		return;
	}

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
		bn_new(m00);
		bn_new(m01);
		bn_new(m10);
		bn_new(m11);
		bn_new(s);
		bn_new(t0);
		bn_new(t1);
		bn_new(u);
		bn_new(v);

		/*
		 * s = (b1 + b2) / 2
		 * m = b2 - s
		 */
		bn_add(s, f->b, g->b);
		bn_rsh(s, s, 1);
		bn_sub(m, g->b, s);

		if (neg) {
			/*
			 * (s, m) <- (-m, -s)
			 *
			 * t0 is otherwise dead at this point.
			 */
			bn_neg(t0, m);
			bn_neg(m, s);
			bn_copy(s, t0);
		}

		/*
		 * F = gcd(a1, a2) = u*a1 + v*a2
		 *
		 * F remains useful only until the nontrivial gcd branch
		 * has computed H. It is subsequently reused as scratch.
		 */
		bn_gcd_ext(F, u, v, f->a, g->a);

		if (bn_cmp_dig(F, 1) == RLC_EQ) {
			bn_set_dig(Ax, 1);

			bn_mul(Bx, m, v);
			bn_copy(By, f->a);
		} else {
			/*
			 * Check whether F divides s.
			 *
			 * t0 is scratch.
			 */
			bn_mod(t0, s, F);

			if (bn_is_zero(t0)) {
				bn_copy(Ax, F);
				bn_mul(Bx, m, v);
				bn_div_exc(By, f->a, Ax);
			} else {
				/*
				 * Ax = gcd(F, s)
				 *
				 * t0 <- x
				 * t1 <- y
				 *
				 * F remains the original gcd and is needed as
				 * input to this gcd computation.
				 */
				bn_gcd_ext(Ax, t0, t1, F, s);

				/*
				 * H = F / Ax
				 */
				bn_div_exc(H, F, Ax);

				/*
				 * Compute
				 *
				 *   l = y * (v*c1 + u*c2) mod H.
				 *
				 * After gcd_ext(), t0=x is dead and t1=y.
				 * F is also dead after this point, so F can hold
				 * the intermediate value and eventually l.
				 */

				/* t0 = v * (f->c mod H) */
				bn_mod(t0, f->c, H);
				bn_mul(t0, t0, v);

				/* F = u * (g->c mod H) */
				bn_mod(F, g->c, H);
				bn_mul(F, F, u);

				/* t0 = v*c1 + u*c2 mod H */
				bn_add(t0, t0, F);
				bn_mod(t0, t0, H);

				/* F = l = y * t0 mod H */
				bn_mul(t0, t0, t1);
				bn_mod(F, t0, H);

				/*
				 * By = f->a / Ax
				 */
				bn_div_exc(By, f->a, Ax);

				/*
				 * Bx = (v*m + l*By) / H
				 *
				 * t0 and t1 are both free now.
				 */
				bn_mul(t0, v, m);
				bn_mul(t1, F, By);
				bn_add(t0, t0, t1);
				bn_div_exc(Bx, t0, H);
			}
		}

		/*
		 * Cy = g->a / Ax
		 * Dy = s / Ax
		 */
		bn_div_exc(Cy, g->a, Ax);
		bn_div_exc(Dy, s, Ax);

		/*
		 * Bx <- Bx mod By
		 *
		 * No quotient is needed, so bn_div_rem() + q is unnecessary.
		 */
		bn_mod(Bx, Bx, By);

		/*
		 * Partial extended gcd:
		 *
		 *   [ Bx ]   [ m00 m01 ] [ ... ]
		 *   [ By ] = [ m10 m11 ] [ ... ]
		 */
		bn_gcd_ext_par(Bx, by, m00, m01, m10, m11, Bx, By, bnd);

		/*
		 * Ay = -m10 * Ax
		 */
		bn_mul(Ay, m10, Ax);
		bn_neg(Ay, Ay);

		/*
		 * Cx = (Bx*Cy - m*m11) / By
		 */
		bn_mul(Cx, Bx, Cy);
		bn_mul_sub(Cx, Cx, m, m11);
		bn_div_exc(Cx, Cx, By);

		/*
		 * Cy
		 */
		if (bn_is_zero(Bx)) {
			bn_mul(Cy, g->a, by);
			bn_mul_sub(Cy, Cy, Ay, m);
			bn_div_exc(Cy, Cy, f->a);
		} else {
			bn_mul(Cy, Cx, by);
			bn_add(Cy, Cy, m);
			bn_div_exc(Cy, Cy, Bx);
		}

		/*
		 * Dx = (Bx*Dy - g->c*m11) / By
		 */
		bn_mul(Dx, Bx, Dy);
		bn_mul_sub(Dx, Dx, g->c, m11);
		bn_div_exc(Dx, Dx, By);

		/*
		 * Dy = (Dy - Dx*m10) / m11
		 */
		bn_mul_sub(Dy, Dy, Dx, m10);
		bn_div_exc(Dy, Dy, m11);

		/*
		 * Ax <- m11 * Ax
		 */
		bn_mul(Ax, m11, Ax);

		/*
		 * Final minors.
		 *
		 * All accesses to f/g are finished at this point, so we can
		 * write directly into r rather than maintaining ra/rb/rc.
		 */

		/* a = by*Cy - Ay*Dy */
		bn_mul(r->a, by, Cy);
		bn_mul_sub(r->a, r->a, Ay, Dy);

		/* c = Bx*Cx - Ax*Dx */
		bn_mul(r->c, Bx, Cx);
		bn_mul_sub(r->c, r->c, Ax, Dx);

		/*
		 * b = Ax*Dy + Ay*Dx - Bx*Cy - by*Cx
		 */
		bn_mul(r->b, Ax, Dy);
		bn_mul_add(r->b, r->b, Ay, Dx);
		bn_mul_sub(r->b, r->b, Bx, Cy);
		bn_mul_sub(r->b, r->b, by, Cx);

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
		bn_free(m);
		bn_free(m00);
		bn_free(m01);
		bn_free(m10);
		bn_free(m11);
		bn_free(s);
		bn_free(t0);
		bn_free(t1);
		bn_free(u);
		bn_free(v);
	}
}