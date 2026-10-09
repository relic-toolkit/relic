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
 * Implementation of point multiplication on prime elliptic curves over an
 * octic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_GLS_IMP(ep8, 16);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_GLS(ep8, fp8, 16, 4);

#endif /* EP_MUL == LWREG */

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_NAF_IMP(ep8);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep8, fp8);

#endif /* EP_MUL == LWREG */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep8);

#if EP_MUL == SLIDE || !defined(STRIP)

TMPL_EP_MUL_SLIDE(ep8);

#endif

#if EP_MUL == MONTY || !defined(STRIP)

TMPL_EP_MUL_MONTY(ep8, fp8);

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep8_mul_lwnaf(ep8_t r, const ep8_t p, const bn_t k) {
	if (bn_is_zero(k) || ep8_is_infty(p)) {
		ep8_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep8_mul_gls_imp(r, p, k);
		return;
	}

	ep8_mul_naf_imp(r, p, k);
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep8_mul_lwreg(ep8_t r, const ep8_t p, const bn_t k) {
	if (bn_is_zero(k) || ep8_is_infty(p)) {
		ep8_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep8_mul_reg_gls(r, p, k);
		return;
	}

	ep8_mul_reg_imp(r, p, k);
}

#endif

TMPL_EP_MUL_GEN(ep8);

TMPL_EP_MUL_DIG(ep8);
