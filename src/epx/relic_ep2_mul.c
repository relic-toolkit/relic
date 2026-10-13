/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2012 RELIC Authors
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
 * Implementation of point multiplication on prime elliptic curves over
 * a quadratic extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"
#include "relic_md.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Multiplies a point by the cofactor in a Barreto-Naehrig curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep2_mul_cof_bn(ep2_t r, const ep2_t p) {
	bn_t x;
	ep2_t t0, t1, t2;

	ep2_null(t0);
	ep2_null(t1);
	ep2_null(t2);
	bn_null(x);

	RLC_TRY {
		ep2_new(t0);
		ep2_new(t1);
		ep2_new(t2);
		bn_new(x);

		fp_prime_get_par(x);

		/* Compute t0 = xP. */
		ep2_mul_basic(t0, p, x);

		/* Compute t1 = \psi(3xP). */
		ep2_dbl(t1, t0);
		ep2_add(t1, t1, t0);
		ep2_norm(t1, t1);
		ep2_frb(t1, t1, 1);

		/* Compute t2 = \psi^3(P) + t0 + t1 + \psi^2(xP). */
		ep2_frb(t2, p, 2);
		ep2_frb(t2, t2, 1);
		ep2_add(t2, t2, t0);
		ep2_add(t2, t2, t1);
		ep2_frb(t1, t0, 2);
		ep2_add(t2, t2, t1);

		ep2_norm(r, t2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(t0);
		ep2_free(t1);
		ep2_free(t2);
		bn_free(x);
	}
}

/**
 * Multiplies a point by the cofactor in a Barreto-Lynn-Scott curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep2_mul_cof_b12(ep2_t r, const ep2_t p) {
	bn_t x;
	ep2_t t0, t1, t2, t3;

	ep2_null(t0);
	ep2_null(t1);
	ep2_null(t2);
	ep2_null(t3);
	bn_null(x);

	RLC_TRY {
		ep2_new(t0);
		ep2_new(t1);
		ep2_new(t2);
		ep2_new(t3);
		bn_new(x);

		fp_prime_get_par(x);

		/* Compute t0 = xP. */
		ep2_mul_basic(t0, p, x);
		/* Compute t1 = [x^2]P. */
		ep2_mul_basic(t1, t0, x);

		/* t2 = (x^2 - x - 1)P = x^2P - x*P - P. */
		ep2_sub(t2, t1, t0);
		ep2_sub(t2, t2, p);
		/* t3 = \psi(x - 1)P. */
		ep2_sub(t3, t0, p);
		ep2_frb(t3, t3, 1);
		ep2_add(t2, t2, t3);
		/* t3 = \psi^2(2P). */
		ep2_dbl(t3, p);
		ep2_frb(t3, t3, 2);
		ep2_add(t2, t2, t3);
		ep2_norm(r, t2);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep2_free(t0);
		ep2_free(t1);
		ep2_free(t2);
		ep2_free(t3);
		bn_free(x);
	}
}

TMPL_EP_MUL_TW_TAB(ep2, fp2);

TMPL_EP_MUL_TW_NAF(ep2, fp2);

TMPL_EP_MUL_TW_REG(ep2, fp2);

/**
 * Multiplies a point by an integer using two tau-adic NAFs or two regular
 * tau-adic expansions, when psi^2 acts on the point as a unit u of Z[w]: the
 * decomposition k = k0 + k1 * psi + k2 * psi^2 + k3 * psi^3 regroups as
 * (k0 + k2 * u) + (k1 + k3 * u) * psi.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 * @param[in] k				- the integer.
 * @param[in] reg			- the flag for the regular method.
 * @return RLC_OK if psi^2 acts as a unit, RLC_ERR otherwise.
 */
static int ep2_mul_tw_imp(ep2_t r, const ep2_t p, const bn_t k, int reg) {
	/* The units (-1)^(j / 3) * w^(j % 3) as u0 + u1 * w. */
	const int u0[6] = { 1, 0, -1, -1, 0, 1 }, u1[6] = { 0, 1, -1, 0, -1, 1 };
	const int s = (reg ? 6 : 3);
	int8_t c[2], naf[2][RLC_FP_BITS + 1];
	size_t l, len[2] = { RLC_FP_BITS + 1, RLC_FP_BITS + 1 };
	int j, result = RLC_ERR;
	bn_t n, x, _k[4], a, b;
	fp2_t beta;
	ep2_t q, t[2][2][12];

	bn_null_all(n, x, a, b);
	fp2_null(beta);
	ep2_null(q);

	RLC_TRY {
		bn_new_all(n, x, a, b);
		fp2_new(beta);
		ep2_new(q);
		for (int i = 0; i < 4; i++) {
			bn_null(_k[i]);
			bn_new(_k[i]);
		}
		for (int i = 0; i < 2; i++) {
			for (int f = 0; f < 2; f++) {
				for (j = 0; j < 12; j++) {
					ep2_null(t[i][f][j]);
					ep2_new(t[i][f][j]);
				}
			}
		}

		fp2_zero(beta);
		fp_copy(beta[0], ep_curve_get_beta());
		ep2_tw_tab(t[0], p, s, beta);

		/* Find the unit (-1)^s * w^e with psi^2(P) = (beta^e * x, (-1)^s * y),
		 * using w^2(x) = -x - w(x). */
		ep2_frb(q, t[0][0][0], 2);
		fp2_add(beta, t[0][0][0]->x, t[0][1][0]->x);
		fp2_neg(beta, beta);
		j = -1;
		for (int e = 0; e < 3; e++) {
			if (fp2_cmp(q->x, e == 0 ? t[0][0][0]->x :
					(e == 1 ? t[0][1][0]->x : beta)) == RLC_EQ) {
				j = e;
			}
		}
		if (j >= 0 && fp2_cmp(q->y, t[0][0][0]->y) != RLC_EQ) {
			fp2_neg(q->y, q->y);
			j = (fp2_cmp(q->y, t[0][0][0]->y) == RLC_EQ ? j + 3 : -1);
		}

		if (j >= 0) {
			ep2_curve_get_ord(n);
			ep_curve_frbase(x);
			/* The subscalars of the Frobenius decomposition are below |x| for
			 * BLS curves and below 2^3 * |x| for BN curves, so the regrouped
			 * coefficients are below 2^l in absolute value. The regular
			 * expansions need more than 2 * (l + 0.06) / log2(27) digits. */
			l = bn_bits(x) + (ep_curve_is_pairf() == EP_BN ? 4 : 1);
			len[0] = len[1] = (20000 * l + 1200) / 47549 + 1;
			bn_mod(_k[0], k, n);
			bn_rec_frb(_k, 4, _k[0], x, n, ep_curve_is_pairf() == EP_BN);
			for (int i = 0; i < 2; i++) {
				/* (k_i + k_(i + 2) * u) = a + b * w. */
				bn_copy(a, _k[i]);
				if (u0[j] > 0) {
					bn_add(a, a, _k[i + 2]);
				} else if (u0[j] < 0) {
					bn_sub(a, a, _k[i + 2]);
				}
				bn_zero(b);
				if (u1[j] > 0) {
					bn_copy(b, _k[i + 2]);
				} else if (u1[j] < 0) {
					bn_neg(b, _k[i + 2]);
				}
				if (reg) {
					bn_rec_retnaf(naf[i], &c[i], len[i], a, b);
				} else {
					len[i] = RLC_FP_BITS + 1;
					bn_rec_etnaf(naf[i], &len[i], a, b);
				}
			}
			/* psi commutes with w and tau, so it maps the table of P to one
			 * of psi(P), keeping the points affine. */
			for (int f = 0; f < 2; f++) {
				for (int i = 0; i < 2 * s; i++) {
					ep2_psi(t[1][f][i], t[0][f][i]);
				}
			}
			if (reg) {
				ep2_tw_reg(r, t, naf, c, len[0], 2);
			} else {
				ep2_tw_naf(r, t, naf, len, 2);
			}
			result = RLC_OK;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, x, a, b);
		fp2_free(beta);
		ep2_free(q);
		for (int i = 0; i < 4; i++) {
			bn_free(_k[i]);
		}
		for (int i = 0; i < 2; i++) {
			for (int f = 0; f < 2; f++) {
				for (j = 0; j < 12; j++) {
					ep2_free(t[i][f][j]);
				}
			}
		}
	}
	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EPX_MUL(ep2, fp2, 4, 1, WNAF);

void ep2_mul_twnaf(ep2_t r, const ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	if (!ep_curve_is_endom() || ep2_curve_opt_a() != RLC_ZERO ||
			ep2_mul_tw_imp(r, p, k, 0) != RLC_OK) {
		ep2_mul_lwnaf(r, p, k);
	}
}

void ep2_mul_twreg(ep2_t r, const ep2_t p, const bn_t k) {
	if (bn_is_zero(k) || ep2_is_infty(p)) {
		ep2_set_infty(r);
		return;
	}

	if (!ep_curve_is_endom() || ep2_curve_opt_a() != RLC_ZERO ||
			ep2_mul_tw_imp(r, p, k, 1) != RLC_OK) {
		ep2_mul_lwreg(r, p, k);
	}
}

void ep2_mul_cof(ep2_t r, const ep2_t p) {
	bn_t k;

	bn_null(k);

	RLC_TRY {
		bn_new(k);

		switch (ep_curve_is_pairf()) {
			case EP_BN:
				ep2_mul_cof_bn(r, p);
				break;
			case EP_B12:
				ep2_mul_cof_b12(r, p);
				break;
			default:
				/* Now, multiply by cofactor to get the correct group. */
				ep2_curve_get_cof(k);
				ep2_mul_big(r, p, k);
				break;
		}		
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(k);
	}
}
