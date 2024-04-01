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
 * Implementation of addition on prime elliptic curves over a quartic
 * extension field.
 *
 * @ingroup epx
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
TMPL_ADD_BASIC_IMP(ep4, fp4);

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

#endif /* EP_ADD == JACOB */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void ep4_add_basic(ep4_t r, const ep4_t p, const ep4_t q) {
	if (ep4_is_infty(p)) {
		ep4_copy(r, q);
		return;
	}

	if (ep4_is_infty(q)) {
		ep4_copy(r, p);
		return;
	}

	ep4_add_basic_imp(r, NULL, p, q);
}

void ep4_add_slp_basic(ep4_t r, fp4_t s, const ep4_t p, const ep4_t q) {
	if (ep4_is_infty(p)) {
		ep4_copy(r, q);
		return;
	}

	if (ep4_is_infty(q)) {
		ep4_copy(r, p);
		return;
	}

	ep4_add_basic_imp(r, s, p, q);
}

#endif

#if EP_ADD == PROJC || !defined(STRIP)

void ep4_add_projc(ep4_t r, const ep4_t p, const ep4_t q) {
	if (ep4_is_infty(p)) {
		ep4_copy(r, q);
		return;
	}

	if (ep4_is_infty(q)) {
		ep4_copy(r, p);
		return;
	}

	ep4_add_projc_imp(r, p, q);
}

#endif

#if EP_ADD == JACOB || !defined(STRIP)

void ep4_add_jacob(ep4_t r, const ep4_t p, const ep4_t q) {
	if (ep4_is_infty(p)) {
		ep4_copy(r, q);
		return;
	}

	if (ep4_is_infty(q)) {
		ep4_copy(r, p);
		return;
	}

	ep4_add_jacob_imp(r, p, q);
}

#endif

void ep4_sub(ep4_t r, const ep4_t p, const ep4_t q) {
	ep4_t t;

	ep4_null(t);

	if (p == q) {
		ep4_set_infty(r);
		return;
	}

	RLC_TRY {
		ep4_new(t);
		ep4_neg(t, q);
		ep4_add(r, p, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep4_free(t);
	}
}
