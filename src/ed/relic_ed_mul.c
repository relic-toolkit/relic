/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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
 * Implementation of the point multiplication on Twisted Edwards elliptic curves.
 *
 * @ingroup ed
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

TMPL_EC_MUL_NAF_IMP(ed, RLC_FP_BITS);

TMPL_EC_MUL_REG_IMP(ed, RLC_FP_BITS);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EC_MUL_BASIC(ed);

TMPL_EC_MUL_MONTY(ed);

void ed_mul_lwnaf(ed_t r, const ed_t p, const bn_t k) {
	if (bn_is_zero(k) || ed_is_infty(p)) {
		ed_set_infty(r);
		return;
	}

	ed_mul_naf_imp(r, p, k);
}

void ed_mul_lwreg(ed_t r, const ed_t p, const bn_t k) {
	if (bn_is_zero(k) || ed_is_infty(p)) {
		ed_set_infty(r);
		return;
	}

	ed_mul_reg_imp(r, p, k);
}

#ifdef ED_PRECO
TMPL_EC_MUL_GEN(ed, preco);
#else
TMPL_EC_MUL_GEN(ed, plain);
#endif

TMPL_EC_MUL_DIG(ed);
