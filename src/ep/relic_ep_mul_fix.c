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
 * Implementation of fixed point multiplication on prime elliptic curves.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies a prime elliptic curve point by an integer using the
 * single-table comb method and the GLV endomorphism.
 *
 * @param[out] r 				- the result.
 * @param[in] t					- the precomputed table.
 * @param[in] k					- the integer.
 */
static void ep_mul_fix_glv(ep_t r, const ep_t *t, const bn_t k) {
	int i, j, l, w0, w1, n0, n1, p0, p1, s0, s1;
	bn_t n, m, k0, k1;
	ep_t u;

	bn_null(n);
	bn_null(m);
	bn_null(k0);
	bn_null(k1);
	ep_null(u);

	RLC_TRY {
		bn_new(n);
		bn_new(m);
		bn_new(k0);
		bn_new(k1);
		ep_new(u);

		ep_curve_get_ord(n);
		l = RLC_CEIL(bn_bits(n), (2 * RLC_DEPTH));

		bn_mod(m, k, n);
		bn_rec_glv(k0, k1, m, n, ep_curve_get_v1(), ep_curve_get_v2());
		s0 = bn_sign(k0);
		s1 = bn_sign(k1);
		bn_abs(k0, k0);
		bn_abs(k1, k1);

		n0 = bn_bits(k0);
		n1 = bn_bits(k1);

		p0 = (RLC_DEPTH) * l - 1;

		ep_set_infty(r);
		if (n0 > p0 + 1) {
			ep_copy(r, t[1 << (RLC_DEPTH-1)]);
		}
		if (n1 > p0 + 1) {
			ep_psi(u, t[1 << (RLC_DEPTH-1)]);
			ep_add(r, r, u);
		}

		for (i = l - 1; i >= 0; i--) {
			ep_dbl(r, r);

			w0 = w1 = 0;
			p1 = p0--;
			for (j = RLC_DEPTH - 1; j >= 0; j--, p1 -= l) {
				w0 = w0 << 1;
				w1 = w1 << 1;
				if (p1 < n0 && bn_get_bit(k0, p1)) {
					w0 = w0 | 1;
				}
				if (p1 < n1 && bn_get_bit(k1, p1)) {
					w1 = w1 | 1;
				}
			}
			if (w0 > 0) {
				if (s0 == RLC_POS) {
					ep_add(r, r, t[w0]);
				} else {
					ep_sub(r, r, t[w0]);
				}
			}
			if (w1 > 0) {
				ep_psi(u, t[w1]);
				if (s1 == RLC_POS) {
					ep_add(r, r, u);
				} else {
					ep_sub(r, r, u);
				}
			}
		}
		ep_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(m);
		bn_free(k0);
		bn_free(k1);
		ep_free(u);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_FIX_BASIC(ep, glv);

TMPL_EP_MUL_FIX_LWREG(ep, fp);

TMPL_EP_MUL_COMBD(ep);
