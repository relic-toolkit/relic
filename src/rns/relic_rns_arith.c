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
	const size_t n = c->n, l = c->d + 1;
	const dig_t *m = c->m, *u = c->u, *p = c->p;
	dig_t w[2 * RLC_RNS_MAX], xi[RLC_RNS_MAX];
	dig_t s[RLC_BN_DIGS + 1], t[RLC_BN_DIGS + 1], a1, b, q;
	dbl_t lo, hi, d, e;
	int k;

	/* w = a / M is the value of a, with -N < w < (n + 1)N. The padding of
	 * the bases is cleared, as only the residues of the moduli are set. */
	dv_zero(w, 2 * c->o);
	rns_wide_imp(w, a, c, n, c->o);
	rns_rdcn_low(w, w, c);
	/* w = sum xi_i (M/m_i) - alpha M, where alpha rounds sum xi_i / m_i, as
	 * w / M is tiny. */
	for (size_t i = 0; i < n; i++) {
		xi[i] = rns_mul(w[i], c->ib[i], m[i], u[i]);
	}
	a1 = rns_alpha(xi, n, 1);
	/* The low digits of w + 3N are enough to recover it, as it is positive.
	 * The multipliers are single digits, so sum them column by column, with
	 * the high halves of the products carried to the next column. */
	d = 0;
	for (size_t j = 0; j < l; j++) {
		lo = d + c->p3[j];
		e = (dbl_t)a1 * c->mm[j];
		lo += (dig_t)e;
		hi = e >> RLC_DIG;
		for (size_t i = 0; i < n; i++) {
			e = (dbl_t)xi[i] * c->mp[i * l + j];
			lo += (dig_t)e;
			hi += e >> RLC_DIG;
		}
		s[j] = (dig_t)lo;
		d = (lo >> RLC_DIG) + hi;
	}
	/* Now 0 < s < (n + 4)N, so subtract 2^k N where it fits, for 2^k at most
	 * n + 3 from the largest down. */
	for (k = 0; ((size_t)2 << k) <= n + 3; k++);
	for (; k >= 0; k--) {
		b = 0;
		for (size_t j = 0; j < l; j++) {
			q = (j < l - 1 ? p[j] << k : 0);
			if (j > 0 && k > 0) {
				q |= p[j - 1] >> (RLC_DIG - k);
			}
			d = (dbl_t)s[j] - q - b;
			t[j] = (dig_t)d;
			b = (dig_t)(d >> RLC_DIG) & 1;
		}
		/* Keep the difference unless it wrapped around. */
		q = b - 1;
		for (size_t j = 0; j < l; j++) {
			s[j] = (t[j] & q) | (s[j] & ~q);
		}
	}
	dv_copy(r, s, c->d);
}

void rns_set(dig_t *r, const dig_t *a, const rns_t c) {
	dig_t t[2 * RLC_RNS_MAX];

	/* The residues of a, stored as a value. */
	rns_digs_low(t, a, c);
	/* Times M^2 / M for Montgomery form. */
	rns_mulm_low(r, t, c->cv, c);
}

int rns_is_zero(const dig_t *a, const rns_t c) {
	const size_t n = c->n, o = c->o;
	const dig_t *m = c->m, *u = c->u;
	dig_t q[RLC_RNS_MAX], r[RLC_RNS_MAX], d, z = 0;

	/* The first half of the reduction gives r = a / M in B', with |r| < 3N,
	 * so a is zero modulo N if and only if r is one of -2N, -N, 0, N or 2N,
	 * which B' tells apart without extending r back to B. */
	dv_zero(q, RLC_RNS_MAX);
	for (size_t i = 0; i < n; i++) {
		q[i] = rns_mul(a[i], c->nq[i], m[i], u[i]);
	}
	rns_extm_low(r, q, 1, 0, c);
	for (size_t i = 0; i < n; i++) {
		r[i] = RLC_RNS_ADD(rns_mul(a[o + i], c->mi[i], m[o + i], u[o + i]),
				r[i], m[o + i]);
	}
	for (size_t k = 0; k < 5; k++) {
		d = 0;
		for (size_t i = 0; i < n; i++) {
			d |= r[i] ^ c->kp[k * 2 * o + o + i];
		}
		z |= (d == 0);
	}
	return (int)z;
}
