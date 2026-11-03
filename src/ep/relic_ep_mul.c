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
 * Implementation of the point multiplication on prime elliptic curves.
 *
 * @ingroup eb
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

static void ep_mul_glv_imp(ep_t r, const ep_t p, const bn_t k) {
	int i, n0, n1, s0, s1;
	int8_t naf0[RLC_FP_BITS + 1], naf1[RLC_FP_BITS + 1], *t0, *t1;
	bn_t n, m, k0, k1;
	ep_t q, t[1 << (RLC_WIDTH - 2)];
	size_t l, l0, l1;

	bn_null_all(n, m, k0, k1);
	ep_null(q);
	for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
		ep_null(t[i]);
	}

	RLC_TRY {
		bn_new_all(n, m, k0, k1);
		ep_new(q);
		for (i = 0; i < (1 << (RLC_WIDTH - 2)); i++) {
			ep_new(t[i]);
		}

		ep_curve_get_ord(n);
		bn_mod(m, k, n);
		bn_rec_glv(k0, k1, m, n, ep_curve_get_v1(), ep_curve_get_v2());
		s0 = bn_sign(k0);
		s1 = bn_sign(k1);

		if (s0 == RLC_POS) {
			ep_copy(q, p);
		} else {
			ep_neg(q, p);
		}
		TMPL_EP_MUL_TAB(ep, t, q, RLC_WIDTH);

		l0 = l1 = RLC_FP_BITS + 1;
		bn_rec_naf(naf0, &l0, k0, RLC_WIDTH);
		bn_rec_naf(naf1, &l1, k1, RLC_WIDTH);

		l = RLC_MAX(l0, l1);
		t0 = naf0 + l - 1;
		t1 = naf1 + l - 1;

		ep_set_infty(r);
		for (i = l - 1; i >= 0; i--, t0--, t1--) {
			ep_dbl(r, r);

			n0 = *t0;
			n1 = *t1;
			if (n0 > 0) {
				ep_add(r, r, t[n0 / 2]);
			}
			if (n0 < 0) {
				ep_sub(r, r, t[-n0 / 2]);
			}
			if (n1 > 0) {
				ep_psi(q, t[n1 / 2]);
				if (s0 != s1) {
					ep_neg(q, q);
				}
				ep_add(r, r, q);
			}
			if (n1 < 0) {
				ep_psi(q, t[-n1 / 2]);
				if (s0 != s1) {
					ep_neg(q, q);
				}
				ep_sub(r, r, q);
			}
		}
		/* Convert r to affine coordinates. */
		ep_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, m, k0, k1);
		ep_free(q);
		for (i = 0; i < 1 << (RLC_WIDTH - 2); i++) {
			ep_free(t[i]);
		}
	}
}

TMPL_EC_MUL_NAF_IMP(ep, RLC_FP_BITS);

/* Joint table of a * P0 + b * P1 for odd a < 4 and 0 <= b < 4, at index
 * 2 * b + (a - 1) / 2: a scan of a larger table costs more than it saves.
 * Method from "Optimizing and securing GLV multiplication over BLS
 * pairings-friendly curves" by Faraoun and El Mrabet at DCC 2025, which
 * adapts "2DT-GLS: Faster and exception-free scalar multiplication in the
 * GLS254 binary curve" by Aardal and Aranha at SAC 2022. */
#define EP_GLV_TAB		8

static void ep_mul_reg_glv(ep_t r, const ep_t p, const bn_t k) {
	int8_t ru[RLC_FP_BITS + 1], rv[RLC_FP_BITS + 1], s[2], b, c, n0, n1;
	bn_t n, m[2];
	ep_t q, p1, t[EP_GLV_TAB], u;
	size_t l;

	bn_null_all(n, m[0], m[1]);
	ep_null_all(q, p1, u);
	for (size_t i = 0; i < EP_GLV_TAB; i++) {
		ep_null(t[i]);
	}

	RLC_TRY {
		bn_new_all(n, m[0], m[1]);
		ep_new_all(q, p1, u);
		for (size_t i = 0; i < EP_GLV_TAB; i++) {
			ep_new(t[i]);
		}

		ep_curve_get_ord(n);
		/* The decomposition runs in constant time for |k| < n. */
		bn_rec_glv(m[0], m[1], k, n, ep_curve_get_v1(), ep_curve_get_v2());
		for (size_t i = 0; i < 2; i++) {
			s[i] = bn_sign(m[i]);
			bn_abs(m[i], m[i]);
		}
		/* The regular recoding needs an odd integer, so m[0] + 1 is taken
		 * when m[0] is even and P0 is subtracted at the end. */
		b = bn_is_even(m[0]);
		m[0]->dp[0] |= b;

		/* P0 = s0 * P and P1 = s1 * psi(P), the former kept in t[0]. */
		ep_norm(t[0], p);
		ep_neg(q, t[0]);
		dv_copy_sec(t[0]->y, q->y, RLC_FP_DIGS, s[0] != RLC_POS);
		ep_psi(p1, t[0]);
		ep_neg(q, p1);
		dv_copy_sec(p1->y, q->y, RLC_FP_DIGS, s[0] != s[1]);

		ep_dbl(q, t[0]);
		ep_add(t[1], t[0], q);
		for (size_t i = 2; i < EP_GLV_TAB; i++) {
			ep_add(t[i], t[i - 2], p1);
		}
		ep_norm_sim(t, (const ep_t *)t, EP_GLV_TAB);

		/* Odd digits of m[0] and digits of m[1] with matching signs. */
		l = RLC_FP_BITS + 1;
		bn_rec_reg(ru, &l, m[0], (bn_bits(n) >> 1) + 2, 3);
		bn_rec_aln(rv, l, m[1], ru, 3);

		fp_set_dig(u->z, 1);
		u->coord = EC_AFFIN;
		ep_set_infty(r);
		for (int i = l - 1; i >= 0; i--) {
			ep_dbl(r, r);
			ep_dbl(r, r);

			c = ru[i] >> 7;
			n0 = ((ru[i] ^ c) - c) >> 1;
			n1 = (rv[i] ^ c) - c;
			n0 += 2 * n1;
			for (int j = 0; j < EP_GLV_TAB; j++) {
				fp_copy_sec(u->x, t[j]->x, j == n0);
				fp_copy_sec(u->y, t[j]->y, j == n0);
			}
			ep_neg(q, u);
			fp_copy_sec(u->y, q->y, c != 0);
			ep_add(r, r, u);
		}

		/* t[0] has P0. */
		ep_sub(u, r, t[0]);
		fp_copy_sec(r->x, u->x, b);
		fp_copy_sec(r->y, u->y, b);
		fp_copy_sec(r->z, u->z, b);

		/* Convert r to affine coordinates. */
		ep_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, m[0], m[1]);
		ep_free_all(q, p1, u);
		for (size_t i = 0; i < EP_GLV_TAB; i++) {
			ep_free(t[i]);
		}
	}
}

TMPL_EC_MUL_REG_IMP(ep, RLC_FP_BITS);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep_mul_basic(ep_t r, const ep_t p, const bn_t k) {
	ep_t t;
	int8_t u, *naf = RLC_ALLOCA(int8_t, bn_bits(k) + 1);
	size_t l;

	ep_null(t);

	if (bn_is_zero(k) || ep_is_infty(p)) {
		ep_set_infty(r);
		RLC_FREE(naf);
		return;
	}

	if (bn_bits(k) <= RLC_DIG) {
		ep_mul_dig(r, p, k->dp[0]);
		if (bn_sign(k) == RLC_NEG) {
			ep_neg(r, r);
		}
		RLC_FREE(naf);
		return;
	}

	RLC_TRY {
		ep_new(t);
		if (naf == NULL) {
			RLC_THROW(ERR_NO_BUFFER);
		}

		l = bn_bits(k) + 1;
		bn_rec_naf(naf, &l, k, 2);
		ep_copy(t, p);
		/* Detect case for point tripling. */
		if (naf[l - 2] == 0 && naf[l - 3] == -1) {
			ep_tpl(t, p);
			l -= 2;
		}
		for (int i = l - 2; i >= 0; i--) {
			ep_dbl(t, t);

			u = naf[i];
			if (u > 0) {
				ep_add(t, t, p);
			} else if (u < 0) {
				ep_sub(t, t, p);
			}
		}

		ep_norm(r, t);
		if (bn_sign(k) == RLC_NEG) {
			ep_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
		RLC_FREE(naf);
	}
}

TMPL_EC_MUL_MONTY(ep);

TMPL_EP_MUL_LWNAF(ep, glv);

/* Conditional compilation of the function below was turned off because it
 * is used by the default for protected scalar multiplication in G1. */
TMPL_EP_MUL_LWREG(ep, glv);

TMPL_EP_MUL_GEN(ep);

void ep_mul_dig(ep_t r, const ep_t p, dig_t k) {
	ep_t t;
	bn_t m;
	int8_t u, naf[RLC_DIG + 1];
	size_t l;

	ep_null(t);
	bn_null(m);

	if (k == 0 || ep_is_infty(p)) {
		ep_set_infty(r);
		return;
	}

	RLC_TRY {
		ep_new(t);
		bn_new(m);

		bn_set_dig(m, k);

		l = RLC_DIG + 1;
		bn_rec_naf(naf, &l, m, 2);

		ep_copy(t, p);
		/* Detect case for point tripling. */
		if (l > 2 && naf[l - 2] == 0 && naf[l - 3] == -1) {
			ep_tpl(t, p);
			l -= 2;
		}
		for (int i = l - 2; i >= 0; i--) {
			ep_dbl(t, t);

			u = naf[i];
			if (u > 0) {
				ep_add(t, t, p);
			} else if (u < 0) {
				ep_sub(t, t, p);
			}
		}

		ep_norm(r, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(t);
		bn_free(m);
	}
}
