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
 * NUDUPL, following van der Poorten's formulation as implemented in BICYCL.
 */
void qf_dup(qf_t r, const qf_t f, const bn_t bnd) {
	bn_t Ax, Ay, Bx, By, Dx, Dy;
	bn_t q, t0, t1;
	bn_t m00, m01, m10, m11;

	bn_null(Ax);
	bn_null(Ay);
	bn_null(Bx);
	bn_null(By);
	bn_null(Dx);
	bn_null(Dy);
	bn_null(q);
	bn_null(t0);
	bn_null(t1);
	bn_null(m00);
	bn_null(m01);
	bn_null(m10);
	bn_null(m11);

	RLC_TRY {
		bn_new(Ax);
		bn_new(Ay);
		bn_new(Bx);
		bn_new(By);
		bn_new(Dx);
		bn_new(Dy);
		bn_new(q);
		bn_new(t0);
		bn_new(t1);
		bn_new(m00);
		bn_new(m01);
		bn_new(m10);
		bn_new(m11);

		/*
		 * Ax = gcd(a, b) = m01*b + m11*a, but only m01 is asked for.
		 *
		 * The second cofactor costs a multiplication and an exact division
		 * inside bn_gcd_ext and it is only needed for Dx. When the gcd is one,
		 * m11 = (1 - m01*b)/a, so
		 *
		 *     Dx = -c*m11 = (c*m01*b - c)/a = (Bx*b - c)/a,
		 *
		 * and that relation survives the reduction of Bx modulo By below,
		 * since subtracting q*By from Bx subtracts q*Dy from Dx. So Dx is
		 * recovered after the reduction from the smaller Bx, which is cheaper
		 * than carrying m11 here. A gcd above one still needs m11, and the
		 * branch below computes it then.
		 */
		bn_gcd_ext(Ax, m01, NULL, f->b, f->a);

		if (bn_cmp_dig(Ax, 1) != RLC_EQ) {
			bn_div_exc(By, f->a, Ax);
			bn_div_exc(Dy, f->b, Ax);
		} else {
			bn_copy(By, f->a);
			bn_copy(Dy, f->b);
		}

		/*
		 * Bx = c*m01
		 */
		bn_mul(Bx, f->c, m01);

		/*
		 * Bx <- Bx mod By
		 *
		 * Simultaneously:
		 *     Dx <- Dx - q*Dy
		 *
		 * q must be retained because it is used here.
		 */
		bn_div_rem(q, t0, Bx, By);
		bn_copy(Bx, t0);

		/* Dx = (Bx*b - c)/a, exact, with Bx already reduced modulo By */
		if (bn_cmp_dig(Ax, 1) == RLC_EQ) {
			bn_mul(Dx, Bx, f->b);
			bn_sub(Dx, Dx, f->c);
			bn_div_exc(Dx, Dx, f->a);
		} else {
			/* the gcd is above one, so m11 is needed after all */
			bn_mul(t0, m01, f->b);
			bn_sub(t0, Ax, t0);
			bn_div_exc(m11, t0, f->a);
			bn_mul(Dx, f->c, m11);
			bn_neg(Dx, Dx);
			bn_mul_sub(Dx, Dx, q, Dy);
		}

		/*
		 * Partial extended gcd:
		 *
		 * [ Bx ]   [ m00 m01 ] [ ... ]
		 * [ By ] = [ m10 m11 ] [ ... ]
		 */
		bn_gcd_ext_par(Bx, By, m00, m01, m10, m11, Bx, By, bnd);

		/*
		 * Apply the inverse matrix to (Ax, 0):
		 *
		 *   Ay = -Ax*m10
		 *   Ax =  Ax*m11
		 */
		bn_mul(Ay, Ax, m10);
		bn_neg(Ay, Ay);
		bn_mul(Ax, Ax, m11);

		/*
		 * Apply the inverse matrix to (Dx, Dy):
		 *
		 *   Dx' = Dx*m11 - Dy*m01
		 *   Dy' = Dy*m00 - Dx*m10
		 *
		 * t0 and t1 hold the new values until both have been computed.
		 */
		bn_mul(t0, Dx, m11);
		bn_mul_sub(t0, t0, Dy, m01);

		bn_mul(t1, Dy, m00);
		bn_mul_sub(t1, t1, Dx, m10);

		bn_copy(Dx, t0);
		bn_copy(Dy, t1);

		/*
		 * Final minors:
		 *
		 *   a = By^2 - Ay*Dy
		 *   c = Bx^2 - Ax*Dx
		 *   b = Ax*Dy + Ay*Dx - 2*By*Bx
		 *
		 * All accesses to f are finished, so write directly to r.
		 */

		/* t1 = 2*By*Bx */
		bn_mul(t1, By, Bx);
		bn_lsh(t1, t1, 1);

		/* a = By^2 - Ay*Dy */
		bn_sqr(r->a, By);
		bn_mul_sub(r->a, r->a, Ay, Dy);

		/* c = Bx^2 - Ax*Dx */
		bn_sqr(r->c, Bx);
		bn_mul_sub(r->c, r->c, Ax, Dx);

		/* b = Ax*Dy + Ay*Dx - 2*By*Bx */
		bn_mul(r->b, Ax, Dy);
		bn_mul_add(r->b, r->b, Ay, Dx);
		bn_sub(r->b, r->b, t1);

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
		bn_free(Dx);
		bn_free(Dy);
		bn_free(q);
		bn_free(t0);
		bn_free(t1);
		bn_free(m00);
		bn_free(m01);
		bn_free(m10);
		bn_free(m11);
	}
}