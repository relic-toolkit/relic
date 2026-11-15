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
#if RLC_ARITH != RLC_AVX512
	rns_extm_imp(r, xi, b, exact, c, c->n, c->o);
#else
	(void)r;
	(void)xi;
	(void)b;
	(void)exact;
	(void)c;
	/* The tables follow the convention of the vector kernels. */
	RLC_THROW(ERR_NO_VALID);
#endif
}

void rns_muln_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c) {
	for (size_t i = 0; i < 2 * c->o; i++) {
		r[i] = rns_mul(a[i], b[i], c->m[i], c->u[i]);
	}
}

void rns_rdcn_low(dig_t *r, const dig_t *a, const rns_t c) {
#if RLC_ARITH != RLC_AVX512
	const size_t n = c->n, o = c->o;
	const dig_t *m = c->m, *u = c->u;
	dig_t q[RLC_RNS_MAX], e[RLC_RNS_MAX];

	/* Only the first n values are used, but the compiler cannot tell. */
	dv_zero(q, RLC_RNS_MAX);
	/* xi_i of q = a * (-N^{-1}) mod M, in B, as plain residues. */
	for (size_t i = 0; i < n; i++) {
		q[i] = rns_mul(a[i], c->nq[i], m[i], u[i]);
	}
	/* q * N for q + kM, as a product in B', with 0 <= k < n: the extra kN
	 * only makes the result larger, so the extension skips alpha. */
	rns_extm_low(e, q, 1, -1, c);
	/* r = (a + q * N) / M in B', as a product carries 1 / M^2 there and a
	 * value 1 / M; and its xi_j for the exact extension. */
	for (size_t j = 0; j < n; j++) {
		r[o + j] = RLC_RNS_ADD(a[o + j], e[j], m[o + j]);
		q[j] = rns_mul(r[o + j], c->ib[o + j], m[o + j], u[o + j]);
	}
	/* r in B, exactly, since |r| < (n + 1)N is far below M'/2. */
	rns_extm_low(r, q, 0, 1, c);
#else
	(void)r;
	(void)a;
	(void)c;
	/* The tables follow the convention of the vector kernels. */
	RLC_THROW(ERR_NO_VALID);
#endif
}

void rns_mulm_low(dig_t *r, const dig_t *a, const dig_t *b, const rns_t c) {
	dig_t t[2 * RLC_RNS_MAX];

	rns_muln_low(t, a, b, c);
	rns_rdcn_low(r, t, c);
}

void rns_digs_low(dig_t *r, const dig_t *a, const rns_t c) {
#if RLC_ARITH != RLC_AVX512
	rns_digs_imp(r, a, c, 2 * c->o, c->w);
#else
	(void)r;
	(void)a;
	(void)c;
	/* Digits of 52 bits are not whole digits of the machine. */
	RLC_THROW(ERR_NO_VALID);
#endif
}
