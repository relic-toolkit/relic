/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * over a nonic extension field.
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
TMPL_ADD_BASIC_IMP(ep9, fp9);

/**
 * Adds a point represented in homogeneous coordinates to a point represented in
 * affine coordinates on an ordinary prime elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the projective point.
 * @param[in] q				- the affine point.
 */
TMPL_ADD_PROJC_MIX(ep9, fp9);

/**
 * Adds two points represented in homogeneous coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_PROJC_IMP(ep9, fp9);

/**
 * Adds a point represented in Jacobian coordinates to a point represented in
 * affine coordinates on an ordinary prime elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the projective point.
 * @param[in] q				- the affine point.
 */
TMPL_ADD_JACOB_MIX(ep9, fp9);

/**
 * Adds two points represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_JACOB_IMP(ep9, fp9);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_ADD_BASIC(ep9, fp9);

TMPL_ADD(ep9, projc);

TMPL_ADD(ep9, jacob);

TMPL_SUB(ep9);

/**
 * Doubles a point represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the point to double.
 */
TMPL_DBL_BASIC_IMP(ep9, fp9);

/**
 * Doubles a point represented in projective coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_PROJC_IMP(ep9, fp9);

/**
 * Doubles a point represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_DBL_JACOB_IMP(ep9, fp9);

TMPL_EP_NORM_IMP(ep9, fp9);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_UTIL(ep9, fp9);

TMPL_EP_RHS(ep9, fp9);

TMPL_EP_BIN(ep9, fp9);

TMPL_EP_CMP(ep9, fp9);

TMPL_EP_NEG(ep9, fp9);

TMPL_DBL_BASIC(ep9, fp9);

TMPL_DBL(ep9, projc);

TMPL_DBL(ep9, jacob);

TMPL_EP_NORM(ep9, fp9);

void ep9_frb(ep9_t r, const ep9_t p, int i) {
	ctx_t *ctx = core_get();

	ep9_copy(r, p);
	for (; i > 0; i--) {
		fp9_frb(r->x, r->x, 1);
		fp9_frb(r->y, r->y, 1);
		fp9_frb(r->z, r->z, 1);
		fp9_mul(r->x, r->x, ctx->ep9_frb[0]);
		fp9_mul(r->y, r->y, ctx->ep9_frb[1]);
	}
}

void ep9_psi(ep9_t r, const ep9_t p) {
	ctx_t *ctx = core_get();

	if (ep9_is_infty(p)) {
		ep9_set_infty(r);
		return;
	}

	/* Compute Frob^11(P), with coordinates in Fp^9 raised to p^11 = p^2. */
	fp9_frb(r->x, p->x, 2);
	fp9_frb(r->y, p->y, 2);
	fp9_frb(r->z, p->z, 2);
	fp9_mul(r->x, r->x, ctx->ep9_frb[2]);
	fp9_mul(r->y, r->y, ctx->ep9_frb[3]);
	r->coord = p->coord;
}
