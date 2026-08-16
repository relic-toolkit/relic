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
	bn_t Ax, Ay, Bx, By, Dx, Dy, q, t0, t1, t2, m00, m01, m10, m11, ra, rb, rc;

	bn_null(Ax);
	bn_null(Ay);
	bn_null(Bx);
	bn_null(By);
	bn_null(Dx);
	bn_null(Dy);
	bn_null(q);
	bn_null(t0);
	bn_null(t1);
	bn_null(t2);
	bn_null(m00);
	bn_null(m01);
	bn_null(m10);
	bn_null(m11);
	bn_null(ra);
	bn_null(rb);
	bn_null(rc);

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
		bn_new(t2);
		bn_new(m00);
		bn_new(m01);
		bn_new(m10);
		bn_new(m11);
		bn_new(ra);
		bn_new(rb);
		bn_new(rc);

		/* Ax = gcd(a, b) = m11*a + m01*b */
		bn_gcd_ext_lower(Ax, m11, m01, f->a, f->b);

		if (bn_cmp_dig(Ax, 1) != RLC_EQ) {
			bn_div(By, f->a, Ax);
			bn_div(Dy, f->b, Ax);
		} else {
			bn_copy(By, f->a);
			bn_copy(Dy, f->b);
		}

		bn_mul(Dx, f->c, m11);
		bn_neg(Dx, Dx);
		bn_mul(Bx, f->c, m01);

		/* Bx <- Bx mod By, and apply [[1, -q], [0, 1]] to (Dx, Dy) */
		bn_div_rem(q, t0, Bx, By);
		bn_copy(Bx, t0);
		bn_mul(t0, q, Dy);
		bn_sub(Dx, Dx, t0);

		bn_gcd_ext_par(Bx, By, m00, m01, m10, m11, Bx, By, d);

		/* apply the inverse matrix to (Ax, 0) and (Dx, Dy) */
		bn_mul(Ay, Ax, m10);
		bn_neg(Ay, Ay);
		bn_mul(Ax, Ax, m11);

		bn_mul(t0, Dx, m11);
		bn_mul(t2, Dy, m01);
		bn_sub(t0, t0, t2);
		bn_mul(Dy, Dy, m00);
		bn_mul(t2, Dx, m10);
		bn_sub(Dy, Dy, t2);
		bn_copy(Dx, t0);

		/* a = By^2 - Ay*Dy, c = Bx^2 - Ax*Dx, b = Ax*Dy + Ay*Dx - 2*By*Bx */
		bn_mul(t1, By, Bx);

		bn_sqr(ra, By);
		bn_mul(t0, Ay, Dy);
		bn_sub(ra, ra, t0);

		bn_sqr(rc, Bx);
		bn_mul(t0, Ax, Dx);
		bn_sub(rc, rc, t0);

		bn_mul(rb, Ax, Dy);
		bn_mul(t0, Ay, Dx);
		bn_add(rb, rb, t0);
		bn_lsh(t1, t1, 1);
		bn_sub(rb, rb, t1);

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
		bn_free(Dx);
		bn_free(Dy);
		bn_free(q);
		bn_free(t0);
		bn_free(t1);
		bn_free(t2);
		bn_free(m00);
		bn_free(m01);
		bn_free(m10);
		bn_free(m11);
		bn_free(ra);
		bn_free(rb);
		bn_free(rc);
	}
}
