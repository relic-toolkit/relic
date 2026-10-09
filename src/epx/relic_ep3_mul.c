/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of point multiplication on prime elliptic curves over a
 * cubic extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if EP_MUL == LWNAF || !defined(STRIP)

static void ep3_mul_gls_imp(ep3_t r, const ep3_t p, const bn_t k) {
	size_t l;
	bn_t n, _k[6], u;
	int8_t even, col, sac[6 * (RLC_FP_BITS + 1)];
	ep3_t q[6], t[1 << 5];

	bn_null(n);
	bn_null(u);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		for (int i = 0; i < 6; i++) {
			bn_null(_k[i]);
			ep3_null(q[i]);
			bn_new(_k[i]);
			ep3_new(q[i]);
		}
		for (int i = 0; i < (1 << 5); i++) {
			ep3_null(t[i]);
			ep3_new(t[i]);
		}

		fp_prime_get_par(u);
		if (ep_curve_is_pairf() == EP_SG18) {
			/* Compute base -3*u for the recoding below. */
			bn_dbl(n, u);
			bn_add(u, u, n);
			bn_neg(u, u);
		}
		ep3_curve_get_ord(n);
		bn_mod(_k[0], k, n);
		bn_rec_frb(_k, 6, _k[0], u, n, ep_curve_is_pairf() == EP_BN);
		even = bn_is_even(_k[0]);
		bn_add_dig(_k[0], _k[0], even);
		ep3_norm(q[0], p);
		for (size_t i = 1; i < 6; i++) {
			ep3_psi(q[i], q[i - 1]);
		}
		for (size_t i = 0; i < 6; i++) {
			if (bn_sign(_k[i]) == RLC_NEG) {
				ep3_neg(q[i], q[i]);
			}
			bn_abs(_k[i], _k[i]);
		}

		ep3_copy(t[0], q[0]);
		for (size_t i = 1; i < (1 << 5); i++) {
			l = util_bits_dig(i);
			ep3_add(t[i], t[i ^ (1 << (l - 1))], q[l]);
		}

		l = RLC_FP_BITS + 1;
		bn_rec_sac(sac, &l, _k, u, 1, 6, bn_bits(n), 0);

		ep3_norm_sim(t + 1, t + 1, (1 << 5) - 1);
		fp3_set_dig(r->z, 1);
		fp3_set_dig(q[1]->z, 1);
		r->coord = q[1]->coord = BASIC;

		ep3_set_infty(r);
		for (int j = l - 1; j >= 0; j--) {
			ep3_dbl(r, r);

			col = 0;
			for (int i = 5; i > 0; i--) {
				col <<= 1;
				col += sac[i * l + j];
			}

			if (sac[j]) {
				ep3_sub(r, r, t[col]);
			} else {
				ep3_add(r, r, t[col]);
			}			
		}

		if (even) {
			ep3_sub(r, r, q[0]);
		}

		/* Convert r to affine coordinates. */
		ep3_norm(r, r);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(u);
		for (int i = 0; i < 6; i++) {
			bn_free(_k[i]);
			ep3_free(q[i]);
		}
		for (int i = 0; i < (1 << 5); i++) {
			ep3_free(t[i]);
		}
	}
}

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_GLS(ep3, fp3, 6, 1);

#endif /* EP_MUL == LWREG */

#if EP_MUL == LWNAF || !defined(STRIP)

TMPL_EP_MUL_NAF_IMP(ep3);

#endif /* EP_MUL == LWNAF */

#if EP_MUL == LWREG || !defined(STRIP)

TMPL_EP_MUL_REG_IMP(ep3, fp3);

#endif /* EP_MUL == LWREG */

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_BASIC(ep3);

#if EP_MUL == SLIDE || !defined(STRIP)

TMPL_EP_MUL_SLIDE(ep3);

#endif

#if EP_MUL == MONTY || !defined(STRIP)

TMPL_EP_MUL_MONTY(ep3, fp3);

#endif

#if EP_MUL == LWNAF || !defined(STRIP)

void ep3_mul_lwnaf(ep3_t r, const ep3_t p, const bn_t k) {
	if (bn_is_zero(k) || ep3_is_infty(p)) {
		ep3_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep3_mul_gls_imp(r, p, k);
		return;
	}

	ep3_mul_naf_imp(r, p, k);
}

#endif

#if EP_MUL == LWREG || !defined(STRIP)

void ep3_mul_lwreg(ep3_t r, const ep3_t p, const bn_t k) {
	if (bn_is_zero(k) || ep3_is_infty(p)) {
		ep3_set_infty(r);
		return;
	}

	if (ep_curve_is_endom()) {
		ep3_mul_reg_gls(r, p, k);
		return;
	}

	ep3_mul_reg_imp(r, p, k);
}

#endif

TMPL_EP_MUL_GEN(ep3);

TMPL_EP_MUL_DIG(ep3);
