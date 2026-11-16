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
 * Implementation of the conversions to and from positional form and the zero
 * test in a Residue Number System.
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

void rns_get_bn(bn_t r, const dig_t *a, const rns_t c) {
	dig_t v[RLC_BN_DIGS];

	rns_get(v, a, c);
	bn_read_raw(r, v, c->d);
}

void rns_set_bn(dig_t *r, const bn_t a, const rns_t c) {
	dig_t v[RLC_BN_DIGS], k[2 * RLC_RNS_MAX];
	dig_t s[2 * RLC_RNS_MAX], t[2 * RLC_RNS_MAX];
	const size_t d = c->d, b = RLC_DIG * d / 2;
	size_t i, j, l = RLC_MAX(RLC_CEIL(a->used, d), 1);

	/* K = 2^(RLC_DIG * d) mod N in Montgomery form, as the square of the
	 * Montgomery form of 2^(RLC_DIG * d / 2), which has d digits. Only an
	 * integer longer than N needs it. */
	if (l > 1) {
		dv_zero(v, d);
		v[b / RLC_DIG] = (dig_t)1 << (b % RLC_DIG);
		rns_set(s, v, c);
		rns_mulm_low(k, s, s, c);
	}

	/* Horner's rule on the blocks of d digits of |a|, from the top one, so
	 * that the time depends on the length of a and not on its digits. */
	for (i = l; i-- > 0;) {
		dv_zero(v, d);
		if (i * d < a->used) {
			dv_copy(v, a->dp + i * d, RLC_MIN(d, a->used - i * d));
		}
		rns_set(t, v, c);
		if (i == l - 1) {
			dv_copy(r, t, 2 * c->o);
		} else {
			rns_mulm_low(s, r, k, c);
			for (j = 0; j < 2 * c->o; j++) {
				s[j] = RLC_RNS_ADD(s[j], t[j], c->m[j]);
			}
			/* Multiplying by one brings the sum back to the bounds of a
			 * product, so that it can be multiplied again. */
			rns_mulm_low(r, s, c->one, c);
		}
	}

	if (bn_sign(a) == RLC_NEG) {
		for (j = 0; j < 2 * c->o; j++) {
			r[j] = RLC_RNS_SUB(0, r[j], c->m[j]);
		}
	}
}

int rns_is_zero(const dig_t *a, const rns_t c) {
	dig_t q[RLC_RNS_MAX], r[RLC_RNS_MAX];

	/* Only the first n values are used, but the compiler cannot tell. */
	dv_zero(q, RLC_RNS_MAX);
	return rns_is_zero_imp(a, c, c->n, c->o, q, r, rns_extm_low);
}
