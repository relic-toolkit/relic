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

void qf_dup(qf_t r, const qf_t f, const bn_t d) {
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
		 * Ax = gcd(a, b) = m11*a + m01*b
		 */
		bn_gcd_ext_lower(Ax, m11, m01, f->a, f->b);

		if (bn_cmp_dig(Ax, 1) != RLC_EQ) {
			bn_div(By, f->a, Ax);
			bn_div(Dy, f->b, Ax);
		} else {
			bn_copy(By, f->a);
			bn_copy(Dy, f->b);
		}

		/*
		 * Dx = -c*m11
		 * Bx =  c*m01
		 */
		bn_mul(Dx, f->c, m11);
		bn_neg(Dx, Dx);
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

		bn_mul(t0, q, Dy);
		bn_sub(Dx, Dx, t0);

		/*
		 * Partial extended gcd:
		 *
		 * [ Bx ]   [ m00 m01 ] [ ... ]
		 * [ By ] = [ m10 m11 ] [ ... ]
		 */
		bn_gcd_ext_par(Bx, By, m00, m01, m10, m11, Bx, By, d);

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
		 * t0 = Dx'
		 * t1 is used for the intermediate products.
		 */
		bn_mul(t0, Dx, m11);
		bn_mul(t1, Dy, m01);
		bn_sub(t0, t0, t1);

		bn_mul(t1, Dy, m00);
		bn_mul(Dy, Dx, m10);
		bn_sub(t1, t1, Dy);

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
		bn_mul(t0, Ay, Dy);
		bn_sub(r->a, r->a, t0);

		/* c = Bx^2 - Ax*Dx */
		bn_sqr(r->c, Bx);
		bn_mul(t0, Ax, Dx);
		bn_sub(r->c, r->c, t0);

		/* b = Ax*Dy + Ay*Dx - 2*By*Bx */
		bn_mul(r->b, Ax, Dy);
		bn_mul(t0, Ay, Dx);
		bn_add(r->b, r->b, t0);
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