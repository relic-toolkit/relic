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
 * Implementation of the point doubling on prime elliptic curves.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_tpl_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

/**
 * Doubles a point represented in affine coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param[out] r			- the result.
 * @param[out] s			- the slope.
 * @param[in] p				- the point to double.
 */
TMPL_TPL_BASIC_IMP(ep, fp);

#endif /* EP_ADD == BASIC */

#if EP_ADD == PROJC || !defined(STRIP)

/**
 * Doubles a point represented in projective coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_TPL_PROJC_IMP(ep, fp);

#endif /* EP_ADD == PROJC */

#if EP_ADD == JACOB || !defined(STRIP)

/**
 * Doubles a point represented in Jacobian coordinates on an ordinary prime
 * elliptic curve.
 *
 * @param r					- the result.
 * @param p					- the point to double.
 */
TMPL_TPL_JACOB_IMP(ep, fp);

#endif /* EP_ADD == JACOB */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_ADD == BASIC || !defined(STRIP)

void ep_tpl_basic(ep_t r, const ep_t p) {
	if (ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

	ep_tpl_basic_imp(r, p);
}

#endif

#if EP_ADD == PROJC || !defined(STRIP)

void ep_tpl_projc(ep_t r, const ep_t p) {
	if (ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

	ep_tpl_projc_imp(r, p);
}

#endif

#if EP_ADD == JACOB || !defined(STRIP)

void ep_tpl_jacob(ep_t r, const ep_t p) {
	if (ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

	ep_tpl_jacob_imp(r, p);
}

#endif
