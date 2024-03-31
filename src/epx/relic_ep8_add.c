/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of addition on prime elliptic curves over an octic extension
 * field.
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
TMPL_ADD_BASIC_IMP(ep8, fp8);

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
TMPL_ADD_PROJC_MIX(ep8, fp8);

/**
 * Adds two points represented in homogeneous coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_PROJC_IMP(ep8, fp8);

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
TMPL_ADD_JACOB_MIX(ep8, fp8);

/**
 * Adds two points represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_JACOB_IMP(ep8, fp8);

#endif /* EP_ADD == JACOB */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void ep8_add_basic(ep8_t r, const ep8_t p, const ep8_t q) {
	if (ep8_is_infty(p)) {
		ep8_copy(r, q);
		return;
	}

	if (ep8_is_infty(q)) {
		ep8_copy(r, p);
		return;
	}

	ep8_add_basic_imp(r, NULL, p, q);
}

void ep8_add_slp_basic(ep8_t r, fp8_t s, const ep8_t p, const ep8_t q) {
	if (ep8_is_infty(p)) {
		ep8_copy(r, q);
		return;
	}

	if (ep8_is_infty(q)) {
		ep8_copy(r, p);
		return;
	}

	ep8_add_basic_imp(r, s, p, q);
}

#endif

#if EP_ADD == PROJC || !defined(STRIP)

void ep8_add_projc(ep8_t r, const ep8_t p, const ep8_t q) {
	if (ep8_is_infty(p)) {
		ep8_copy(r, q);
		return;
	}

	if (ep8_is_infty(q)) {
		ep8_copy(r, p);
		return;
	}

	ep8_add_projc_imp(r, p, q);
}

#endif

#if EP_ADD == JACOB || !defined(STRIP)

void ep8_add_jacob(ep8_t r, const ep8_t p, const ep8_t q) {
	if (ep8_is_infty(p)) {
		ep8_copy(r, q);
		return;
	}

	if (ep8_is_infty(q)) {
		ep8_copy(r, p);
		return;
	}

	ep8_add_jacob_imp(r, p, q);
}

#endif

void ep8_sub(ep8_t r, const ep8_t p, const ep8_t q) {
	ep8_t t;

	ep8_null(t);

	if (p == q) {
		ep8_set_infty(r);
		return;
	}

	RLC_TRY {
		ep8_new(t);
		ep8_neg(t, q);
		ep8_add(r, p, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep8_free(t);
	}
}
