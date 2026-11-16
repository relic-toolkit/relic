/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of the low-level arithmetic in a Residue Number System, for
 * the sizes of a context.
 *
 * @ingroup rns
 */

#include "relic_core.h"
#include "relic_rns_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void rns_extm_low(dig_t *r, const dig_t *xi, int b, int exact, const rns_t c) {
	rns_extm_imp(r, xi, b, exact, c, c->n, c->o);
}

void rns_muln_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c) {
	for (size_t i = 0; i < 2 * c->o; i++) {
		r[i] = rns_mul(a[i], b[i], c->m[i], c->u[i]);
	}
}

void rns_rdcn_low(dig_t *r, const dig_t *a, const rns_t c) {
	dig_t q[RLC_RNS_MAX], e[RLC_RNS_MAX];

	/* Only the first n values are used, but the compiler cannot tell. */
	dv_zero(q, RLC_RNS_MAX);
	rns_rdcn_imp(r, a, c, c->n, c->o, q, e, rns_extm_low);
}

void rns_mulm_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c) {
	dig_t t[2 * RLC_RNS_MAX];

	rns_muln_low(t, a, b, c);
	rns_rdcn_low(r, t, c);
}

void rns_digs_low(dig_t *r, const dig_t *a, const rns_t c) {
	rns_digs_imp(r, a, c, 2 * c->o, c->w);
}
