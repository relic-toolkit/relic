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
 * Implementation of the conversions to positional form and the zero test in a
 * Residue Number System.
 *
 * @ingroup rns
 */

#include "relic_core.h"
#include "relic_rns_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void rns_get(dig_t *r, const dig_t *a, const rns_t c) {
	dig_t w[2 * RLC_RNS_MAX], xi[RLC_RNS_MAX];
	dig_t s[RLC_BN_DIGS + 1], t[RLC_BN_DIGS + 1];

	/* The padding of the bases is cleared, as only the residues of the moduli
	 * are set. */
	dv_zero(w, 2 * c->o);
	rns_get_imp(r, a, c, c->n, c->o, c->d, w, xi, s, t, rns_rdcn_low);
}

void rns_set(dig_t *r, const dig_t *a, const rns_t c) {
	dig_t t[2 * RLC_RNS_MAX];

	/* The residues of a, stored as a value. */
	rns_digs_low(t, a, c);
	/* Times M^2 / M for Montgomery form. */
	rns_mulm_low(r, t, c->cv, c);
}

int rns_is_zero(const dig_t *a, const rns_t c) {
	dig_t q[RLC_RNS_MAX], r[RLC_RNS_MAX];

	/* Only the first n values are used, but the compiler cannot tell. */
	dv_zero(q, RLC_RNS_MAX);
	return rns_is_zero_imp(a, c, c->n, c->o, q, r, rns_extm_low);
}
