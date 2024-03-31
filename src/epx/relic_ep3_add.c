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
 * Implementation of addition on prime elliptic curves over a cubic extension
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
TMPL_ADD_BASIC_IMP(ep3, fp3);

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
TMPL_ADD_PROJC_MIX(ep3, fp3);

/**
 * Adds two points represented in homogeneous coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_PROJC_IMP(ep3, fp3);

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
TMPL_ADD_JACOB_MIX(ep3, fp3);

/**
 * Adds two points represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the first point to add.
 * @param[in] q				- the second point to add.
 */
TMPL_ADD_JACOB_IMP(ep3, fp3);

#endif /* EP_ADD == JACOB */

/*============================================================================*/
	/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void ep3_add_basic(ep3_t r, const ep3_t p, const ep3_t q) {
	if (ep3_is_infty(p)) {
		ep3_copy(r, q);
		return;
	}

	if (ep3_is_infty(q)) {
		ep3_copy(r, p);
		return;
	}

	ep3_add_basic_imp(r, NULL, p, q);
}

void ep3_add_slp_basic(ep3_t r, fp3_t s, const ep3_t p, const ep3_t q) {
	if (ep3_is_infty(p)) {
		ep3_copy(r, q);
		return;
	}

	if (ep3_is_infty(q)) {
		ep3_copy(r, p);
		return;
	}

	ep3_add_basic_imp(r, s, p, q);
}

#endif

#if EP_ADD == PROJC || !defined(STRIP)

void ep3_add_projc(ep3_t r, const ep3_t p, const ep3_t q) {
	if (ep3_is_infty(p)) {
		ep3_copy(r, q);
		return;
	}

	if (ep3_is_infty(q)) {
		ep3_copy(r, p);
		return;
	}

	ep3_add_projc_imp(r, p, q);
}

#endif

#if EP_ADD == JACOB || !defined(STRIP)

void ep3_add_jacob(ep3_t r, const ep3_t p, const ep3_t q) {
	if (ep3_is_infty(p)) {
		ep3_copy(r, q);
		return;
	}

	if (ep3_is_infty(q)) {
		ep3_copy(r, p);
		return;
	}

	ep3_add_jacob_imp(r, p, q);
}

#endif

void ep3_sub(ep3_t r, const ep3_t p, const ep3_t q) {
	ep3_t t;

	ep3_null(t);

	if (p == q) {
		ep3_set_infty(r);
		return;
	}

	RLC_TRY {
		ep3_new(t);
		ep3_neg(t, q);
		ep3_add(r, p, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep3_free(t);
	}
}
