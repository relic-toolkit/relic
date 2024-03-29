/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the point addition on prime elliptic curves.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_add_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

/**
 * Adds two points represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_BASIC_IMP(ep, fp);

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || !defined(STRIP)

/**
 * Adds a point represented in homogeneous coordinates to a point represented in
 * affine coordinates on an ordinary prime elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the projective point.
 * @param[in] q				- the affine point.
 */
TMPL_ADD_PROJC_MIX(ep, fp);

/**
 * Adds two points represented in homogeneous coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_PROJC_IMP(ep, fp);

#endif /* EP_ADD == PROJC */

#if EP_ADD == JACOB || !defined(STRIP)

/**
 * Adds a point represented in Jacobian coordinates to a point represented in
 * affine coordinates on an ordinary prime elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the projective point.
 * @param[in] q				- the affine point.
 */
TMPL_ADD_JACOB_MIX(ep, fp);

/**
 * Adds two points represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_JACOB_IMP(ep, fp);

#endif /* EP_ADD == JACOB */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void ep_add_basic(ep_t r, const ep_t p, const ep_t q) {
	if (ep_is_infty(p)) {
		ep_copy(r, q);
		return;
	}

	if (ep_is_infty(q)) {
		ep_copy(r, p);
		return;
	}

	ep_add_basic_imp(r, NULL, p, q);
}

void ep_add_slp_basic(ep_t r, fp_t s, const ep_t p, const ep_t q) {
	if (ep_is_infty(p)) {
		ep_copy(r, q);
		return;
	}

	if (ep_is_infty(q)) {
		ep_copy(r, p);
		return;
	}

	ep_add_basic_imp(r, s, p, q);
}

#endif

#if EP_ADD == PROJC || !defined(STRIP)

void ep_add_projc(ep_t r, const ep_t p, const ep_t q) {
	if (ep_is_infty(p)) {
		ep_copy(r, q);
		return;
	}

	if (ep_is_infty(q)) {
		ep_copy(r, p);
		return;
	}

	ep_add_projc_imp(r, p, q);
}

#endif

#if EP_ADD == JACOB || !defined(STRIP)

void ep_add_jacob(ep_t r, const ep_t p, const ep_t q) {
	if (ep_is_infty(p)) {
		ep_copy(r, q);
		return;
	}

	if (ep_is_infty(q)) {
		ep_copy(r, p);
		return;
	}

	ep_add_jacob_imp(r, p, q);
}

#endif

void ep_sub(ep_t r, const ep_t p, const ep_t q) {
	ep_t t;

	ep_null(t);

	if (p == q) {
		ep_set_infty(r);
		return;
	}

	RLC_TRY {
		ep_new(t);
		ep_neg(t, q);
		ep_add(r, p, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
	}
}
