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
 * Implementation of point arithmetic and utilities on prime elliptic curves
 * over an octic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_util_tmpl.h"
#include "relic_ep_add_tmpl.h"
#include "relic_ep_dbl_tmpl.h"
#include "relic_ep_map_tmpl.h"
#include "relic_md.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_ARITH(ep8, fp8);

TMPL_EP_RHS(ep8, fp8);

TMPL_EP_BIN(ep8, fp8);

void ep8_frb(ep8_t r, const ep8_t p, int i) {
	ctx_t *ctx = core_get();

	ep8_copy(r, p);
	for (; i > 0; i--) {
		fp8_frb(r->x, r->x, 1);
		fp8_frb(r->y, r->y, 1);
		fp8_frb(r->z, r->z, 1);
		fp8_mul(r->x, r->x, ctx->ep8_frb[0]);
		fp8_mul(r->y, r->y, ctx->ep8_frb[1]);
	}
}

void ep8_psi(ep8_t r, const ep8_t p) {
	ep8_frb(r, p, 1);
}

TMPL_EP_MAP(ep8, fp8);
