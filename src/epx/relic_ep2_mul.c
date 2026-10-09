/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of point multiplication on prime elliptic curves over a
 * quadratic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_GLS_IMP(ep2, 4);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_GLS(ep2, fp2, 4, 1);

#endif /* EP_MUL == LWREG */

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_NAF_IMP(ep2);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep2, fp2);

#endif /* EP_MUL == LWREG */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep2);

#if EP_MUL == SLIDE || !defined(STRIP)

TMPL_EP_MUL_SLIDE(ep2);

#endif

#if EP_MUL == MONTY || !defined(STRIP)

TMPL_EP_MUL_MONTY(ep2, fp2);

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep2_mul_lwnaf(ep2_t r, const ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep2_mul_gls_imp(r, p, k);
		return;
	}

	ep2_mul_naf_imp(r, p, k);
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep2_mul_lwreg(ep2_t r, const ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep2_mul_reg_gls(r, p, k);
		return;
	}

	ep2_mul_reg_imp(r, p, k);
}

#endif

TMPL_EP_MUL_GEN(ep2);

TMPL_EP_MUL_DIG(ep2);
