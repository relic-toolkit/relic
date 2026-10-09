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
 * Implementation of fixed point multiplication on binary elliptic curves.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_FIX == LWNAF || !defined(STRIP)

/**
 * Multiplies a binary elliptic curve point by an integer using the w-NAF
 * method.
 *
 * @param[out] r 				- the result.
 * @param[in] t					- the precomputed table.
 * @param[in] k					- the integer.
 */
static void ep_mul_fix_plain(ep_t r, const ep_t *t, const bn_t k) {
	int i, n;
	int8_t naf[RLC_FP_BITS + 1];
	size_t l;

	/* Compute the w-TNAF representation of k. */
	l = RLC_FP_BITS + 1;
	bn_rec_naf(naf, &l, k, RLC_DEPTH);

	n = naf[l - 1];
	if (n > 0) {
		ep_copy(r, t[n / 2]);
	} else {
		ep_neg(r, t[-n / 2]);
	}

	for (i = l - 2; i >= 0; i--) {
		ep_dbl(r, r);

		n = naf[i];
		if (n > 0) {
			ep_add(r, r, t[n / 2]);
		}
		if (n < 0) {
			ep_sub(r, r, t[-n / 2]);
		}
	}
	/* Convert r to affine coordinates. */
	ep_norm(r, r);
	if (bn_sign(k) == RLC_NEG) {
		ep_neg(r, r);
	}
}

#endif /* EP_FIX == LWNAF */

#if EP_FIX == COMBS || !defined(STRIP)


/**
 * Multiplies a prime elliptic curve point by an integer using the COMBS
 * method.
 *
 * @param[out] r 				- the result.
 * @param[in] t					- the precomputed table.
 * @param[in] k					- the integer.
 */
static void ep_mul_combs_endom(ep_t r, const ep_t *t, const bn_t k) {
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


/**
 * Multiplies a prime elliptic curve point by an integer using the COMBS
 * method.
 *
 * @param[out] r 				- the result.
 * @param[in] t					- the precomputed table.
 * @param[in] k					- the integer.
 */
static void ep_mul_combs_plain(ep_t r, const ep_t *t, const bn_t k) {
	int i, j, l, w, n0, p0, p1;
	bn_t n, m;

	bn_null(n);
	bn_null(m);

	RLC_TRY {
		bn_new(n);
		bn_new(m);

		ep_curve_get_ord(n);
		l = RLC_CEIL(bn_bits(n), RLC_DEPTH);

		bn_mod(m, k, n);
		n0 = bn_bits(m);
		p0 = (RLC_DEPTH) * l - 1;

		w = 0;
		p1 = p0--;
		for (j = RLC_DEPTH - 1; j >= 0; j--, p1 -= l) {
			w = w << 1;
			if (p1 < n0 && bn_get_bit(m, p1)) {
				w = w | 1;
			}
		}

		ep_copy(r, t[w]);
		for (i = l - 2; i >= 0; i--) {
			ep_dbl(r, r);

			w = 0;
			p1 = p0--;
			for (j = RLC_DEPTH - 1; j >= 0; j--, p1 -= l) {
				w = w << 1;
				if (p1 < n0 && bn_get_bit(m, p1)) {
					w = w | 1;
				}
			}
			if (w > 0) {
				ep_add(r, r, t[w]);
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
	}
}


#endif /* EP_FIX == LWNAF */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_FIX == BASIC || !defined(STRIP)

TMPL_EP_MUL_FIX_BASIC(ep);

#endif

#if EP_FIX == COMBS || !defined(STRIP)

void ep_mul_pre_combs(ep_t *t, const ep_t p) {
	int i, j, l;
	bn_t n;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		ep_curve_get_ord(n);
		l = RLC_CEIL(bn_bits(n), RLC_DEPTH);

		if (ep_curve_is_endom()) {
			l = RLC_CEIL(bn_bits(n), 2 * RLC_DEPTH);
		}

		ep_set_infty(t[0]);

		ep_copy(t[1], p);
		for (j = 1; j < RLC_DEPTH; j++) {
			ep_dbl(t[1 << j], t[1 << (j - 1)]);
			for (i = 1; i < l; i++) {
				ep_dbl(t[1 << j], t[1 << j]);
			}
			ep_norm(t[1 << j], t[1 << j]);
			for (i = 1; i < (1 << j); i++) {
				ep_add(t[(1 << j) + i], t[i], t[1 << j]);
			}
		}

		ep_norm_sim(t + 2, (const ep_t *)t + 2, RLC_EP_TABLE_COMBS - 2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
	}
}

void ep_mul_fix_combs(ep_t r, const ep_t *t, const bn_t k) {
	if (bn_is_zero(k)) {
		ep_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep_mul_combs_endom(r, t, k);
		return;
	}

	ep_mul_combs_plain(r, t, k);
}
#endif

#if EP_FIX == COMBD || !defined(STRIP)

TMPL_EP_MUL_COMBD(ep);

#endif

#if EP_FIX == LWNAF || !defined(STRIP)

void ep_mul_pre_lwnaf(ep_t *t, const ep_t p) {
	ep_tab(t, p, RLC_DEPTH);
}

void ep_mul_fix_lwnaf(ep_t r, const ep_t *t, const bn_t k) {
	bn_t n, m;

	if (bn_is_zero(k)) {
		ep_set_infty(r);
		return;
	}

	bn_null(n);
	bn_null(m);

	RLC_TRY {
		bn_new(n);
		bn_new(m);

		ep_curve_get_ord(n);
		bn_mod(m, k, n);
		ep_mul_fix_plain(r, t, m);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(m);
	}
}

#endif
