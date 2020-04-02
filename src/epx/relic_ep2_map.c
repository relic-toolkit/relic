/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Implementation of hashing to a prime elliptic curve over a quadratic
 * extension.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_md.h"
#include "relic_tmpl_map.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#ifdef EP_CTMAP
/**
 * Evaluate a polynomial represented by its coefficients using Horner's rule.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the input value.
 * @param[in] coeffs		- the vector of coefficients in the polynomial.
 * @param[in] len			- the degree of the polynomial.
 */
TMPL_MAP_HORNER(fp2, fp2_t)

/**
 * Generic isogeny map evaluation for use with SSWU map.
 */
TMPL_MAP_ISOGENY_MAP(2)
#endif /* EP_CTMAP */

/**
 * Simplified SWU mapping.
 */
#define EP2_MAP_COPY_COND(O, I, C)                                                       \
	do {                                                                                 \
		dv_copy_cond(O[0], I[0], RLC_FP_DIGS, C);                                        \
		dv_copy_cond(O[1], I[1], RLC_FP_DIGS, C);                                        \
	} while (0)
TMPL_MAP_SSWU(2,fp_t,EP2_MAP_COPY_COND)

/**
 * Shallue--van de Woestijne map.
 */
TMPL_MAP_SVDW(2,fp_t,EP2_MAP_COPY_COND)
#undef EP2_MAP_COPY_COND

/**
 * Multiplies a point by the cofactor in a Barreto-Naehrig curve.
 *
 * @param[out] r			- the result.
 * @param[in] p				- the point to multiply.
 */
static void ep2_mul_cof_bn(ep2_t r, ep2_t p) {
	bn_t x;
	ep2_t t0, t1, t2;

	ep2_null(t0);
	ep2_null(t1);
	ep2_null(t2);
	bn_null(x);

	TRY {
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
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
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
static void ep2_mul_cof_b12(ep2_t r, ep2_t p) {
	bn_t x;
	ep2_t t0, t1, t2, t3;

	ep2_null(t0);
	ep2_null(t1);
	ep2_null(t2);
	ep2_null(t3);
	bn_null(x);

	TRY {
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
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		ep2_free(t0);
		ep2_free(t1);
		ep2_free(t2);
		ep2_free(t3);
		bn_free(x);
	}
}

/* caution: this function overwrites k, which it uses as an auxiliary variable */
static inline int fp2_sgn0(const fp2_t t, bn_t k) {
	const int t_0_zero = fp_is_zero(t[0]);

	fp_prime_back(k, t[0]);
	const int t_0_neg = bn_get_bit(k, 0);

	fp_prime_back(k, t[1]);
	const int t_1_neg = bn_get_bit(k, 0);

	/* t[0] == 0 ? sgn0(t[1]) : sgn0(t[0]) */
	return t_0_neg | (t_0_zero & t_1_neg);
}

void ep2_map_impl(ep2_t p, const uint8_t *msg, int len, const uint8_t *dst, int dst_len) {
	bn_t k;
	fp2_t t;
	ep2_t q;
	int neg;
	/* enough space for two extension field elements plus extra bytes for uniformity */
	const int len_per_elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t *pseudo_random_bytes = RLC_ALLOCA(uint8_t, 4 * len_per_elm);

	bn_null(k);
	fp2_null(t);
	ep2_null(q);

	TRY {
		bn_new(k);
		fp2_new(t);
		ep2_new(q);

		/* which hash function should we use? */
		const int abNeq0 = (ep2_curve_opt_a() != RLC_ZERO) && (ep2_curve_opt_b() != RLC_ZERO);
		void (*const map_fn)(ep2_t, fp2_t) = (ep2_curve_is_ctmap() || abNeq0) ? ep2_map_sswu : ep2_map_svdw;

		/* XXX(rsw) See note in ep/relic_ep_map.c about using MD_MAP. */
		/* hash to a pseudorandom string using md_xmd */
		md_xmd(pseudo_random_bytes, 4 * len_per_elm, msg, len, dst, dst_len);

#define EP2_MAP_CONVERT_BYTES(IDX)                                                       \
	do {                                                                                 \
		bn_read_bin(k, pseudo_random_bytes + 2 * IDX * len_per_elm, len_per_elm);        \
		fp_prime_conv(t[0], k);                                                          \
		bn_read_bin(k, pseudo_random_bytes + (2 * IDX + 1) * len_per_elm, len_per_elm);  \
		fp_prime_conv(t[1], k);                                                          \
	} while (0)

#define EP2_MAP_APPLY_MAP(PT)                                                            \
	do {                                                                                 \
		/* sign of t */                                                                  \
		neg = fp2_sgn0(t, k);                                                            \
		/* convert */                                                                    \
		map_fn(PT, t);                                                                   \
		/* compare sign of y to sign of t; fix if necessary */                           \
		neg = neg != fp2_sgn0(PT->y, k);                                                 \
		fp2_neg(t, PT->y);                                                               \
		dv_copy_cond(PT->y[0], t[0], RLC_FP_DIGS, neg);                                  \
		dv_copy_cond(PT->y[1], t[1], RLC_FP_DIGS, neg);                                  \
	} while (0)

		/* first map invocation */
		EP2_MAP_CONVERT_BYTES(0);
		EP2_MAP_APPLY_MAP(p);
		TMPL_MAP_CALL_ISOMAP(2,p);

		/* second map invocation */
		EP2_MAP_CONVERT_BYTES(1);
		EP2_MAP_APPLY_MAP(q);
		TMPL_MAP_CALL_ISOMAP(2,q);

		/* XXX(rsw) could add p and q and then apply isomap,
		 * but need ep_add to support addition on isogeny curves */

#undef EP2_MAP_CONVERT_BYTES
#undef EP2_MAP_APPLY_MAP

		/* sum the result */
		ep2_add(p, p, q);
		ep2_norm(p, p);

		/* clear cofactor */
		switch (ep_curve_is_pairf()) {
			case EP_BN:
				ep2_mul_cof_bn(p, p);
				break;
			case EP_B12:
				ep2_mul_cof_b12(p, p);
				break;
			default:
				/* Now, multiply by cofactor to get the correct group. */
				ep2_curve_get_cof(k);
				if (bn_bits(k) < RLC_DIG) {
					ep2_mul_dig(p, p, k->dp[0]);
				} else {
					ep2_mul_basic(p, p, k);
				}
				break;
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(k);
		fp2_free(t);
		ep2_free(q);
		RLC_FREE(pseudo_random_bytes);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep2_map(ep2_t p, const uint8_t *msg, int len) {
	ep2_map_impl(p, msg, len, (const uint8_t *)"RELIC", 5);
}
