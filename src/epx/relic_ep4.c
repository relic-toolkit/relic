/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Implementation of point arithmetic and utilities on prime elliptic curves
 * over a quartic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_util_tmpl.h"
#include "relic_ep_add_tmpl.h"
#include "relic_ep_dbl_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Adds two points represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_BASIC_IMP(ep4, fp4);

/**
 * Adds a point represented in homogeneous coordinates to a point represented in
 * affine coordinates on an ordinary prime elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the projective point.
 * @param[in] q				- the affine point.
 */
TMPL_ADD_PROJC_MIX(ep4, fp4);

/**
 * Adds two points represented in homogeneous coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_PROJC_IMP(ep4, fp4);

/**
 * Adds a point represented in Jacobian coordinates to a point represented in
 * affine coordinates on an ordinary prime elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the projective point.
 * @param[in] q				- the affine point.
 */
TMPL_ADD_JACOB_MIX(ep4, fp4);

/**
 * Adds two points represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_JACOB_IMP(ep4, fp4);

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

TMPL_ADD_BASIC(ep4, fp4);

TMPL_ADD(ep4, projc);

TMPL_ADD(ep4, jacob);

TMPL_SUB(ep4);

/**
 * Doubles a point represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the point to double.
 */
TMPL_DBL_BASIC_IMP(ep4, fp4);

/**
 * Doubles a point represented in projective coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_PROJC_IMP(ep4, fp4);

/**
 * Doubles a point represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_JACOB_IMP(ep4, fp4);

TMPL_EP_NORM_IMP(ep4, fp4);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_UTIL(ep4, fp4);

TMPL_EP_RHS(ep4, fp4);

TMPL_EP_BIN(ep4, fp4);

TMPL_EP_CMP(ep4, fp4);

TMPL_EP_NEG(ep4, fp4);

TMPL_DBL_BASIC(ep4, fp4);

TMPL_DBL(ep4, projc);

TMPL_DBL(ep4, jacob);

TMPL_EP_NORM(ep4, fp4);

void ep4_frb(ep4_t r, const ep4_t p, int i) {
	ep4_copy(r, p);
	for (; i > 0; i--) {
		fp4_frb(r->x, r->x, 1);
		fp4_frb(r->y, r->y, 1);
		fp4_frb(r->z, r->z, 1);
		fp4_mul_frb(r->x, r->x, 1, 2);
		fp4_mul_frb(r->y, r->y, 1, 3);
	}
}


void ep4_psi(ep4_t r, const ep4_t p) {
	ep4_t q;

	ep4_null(q);

	if (ep4_is_infty(p)) {
		ep4_set_infty(r);
		return;
	}

	RLC_TRY {
		ep4_new(q);

		ep4_copy(r, p);

		switch (ep_curve_is_pairf()) {
			case EP_K16:
				/* u = (2*p^5 - p) mod r */
				ep4_frb(q, p, 1);
				ep4_frb(r, q, 4);
				ep4_dbl(r, r);
				ep4_sub(r, r, q);
				break;
			case EP_AFG16:
				/* u = -p^5 mod r */
				ep4_frb(r, p, 5);
				ep4_neg(r, r);
				break;
			case EP_FM16:
				/* u = p mod r */
			default:
				ep4_frb(r, p, 1);
				break;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep4_free(q);
	}
}



