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
 * Implementation of hashing to a prime elliptic curve.
 *
 * @ingroup ep
 */

#include "relic_core.h"
#include "relic_md.h"
#include "relic_tmpl_map.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#ifdef EP_CTMAP

/**
 * Evaluate a polynomial represented by its coefficients over a using Horner's
 * rule. Might promove to an API if needed elsewhere in the future.
 *
 * @param[out] c		- the result.
 * @param[in] a			- the input value.
 * @param[in] coeffs	- the vector of coefficients in the polynomial.
 * @param[in] deg 		- the degree of the polynomial.
 */
TMPL_MAP_HORNER(fp, fp_st)

/**
 * Generic isogeny map evaluation for use with SSWU map.
 */
TMPL_MAP_ISOGENY_MAP()
#endif /* EP_CTMAP */

/**
 * Simplified SWU mapping from Section 4 of
 * "Fast and simple constant-time hashing to the BLS12-381 Elliptic Curve"
 */
#define EP_MAP_COPY_COND(O, I, C) dv_copy_cond(O, I, RLC_FP_DIGS, C)
TMPL_MAP_SSWU(,dig_t,EP_MAP_COPY_COND)

/**
 * Shallue--van de Woestijne map, based on the definition from
 * draft-irtf-cfrg-hash-to-curve-06, Section 6.6.1
 */
TMPL_MAP_SVDW(,dig_t,EP_MAP_COPY_COND)
#undef EP_MAP_COPY_COND

void ep_map_impl(ep_t p, const uint8_t *msg, int len, const uint8_t *dst, int dst_len) {
	bn_t k, pm1o2;
	fp_t t;
	ep_t q;
	int neg;
	/* enough space for two field elements plus extra bytes for uniformity */
	uint8_t pseudo_random_bytes[66 + 2 * (FP_PRIME + 7) / 8] = {0,};

	bn_null(k);
	bn_null(pm1o2);
	fp_null(t);
	ep_null(q);

	TRY {
		bn_new(k);
		bn_new(pm1o2);
		fp_new(t);
		ep_new(q);

		/* figure out which hash function to use */
		const int abNeq0 = (ep_curve_opt_a() != RLC_ZERO) && (ep_curve_opt_b() != RLC_ZERO);
		void (*const map_fn)(ep_t, fp_t) = (ep_curve_is_ctmap() || abNeq0) ? ep_map_sswu : ep_map_svdw;

		/* XXX(rsw) Using (p-1)/2 for sign of y is the sgn0_be variant from
		 *          draft-irtf-cfrg-hash-to-curve-06. Not all curves want to
		 *          use this variant! This should be fixed per-curve, probably
		 *          using a separate sgn0 function.
		 */
		/* need (p-1)/2 for fixing sign of y */
		pm1o2->sign = RLC_POS;
		pm1o2->used = RLC_FP_DIGS;
		dv_copy(pm1o2->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_hlv(pm1o2, pm1o2);

		/* for hash_to_field, need to hash to a pseudorandom string */
		/* XXX(rsw) the below assumes that we want to use MD_MAP for hashing.
		 *          Consider making the hash function a per-curve option!
		 */
		const int len_per_elm = (FP_PRIME + ep_param_level() + 7) / 8;
		md_xmd(pseudo_random_bytes, 2 * len_per_elm, msg, len, dst, dst_len);

#define EP_MAP_CONVERT_BYTES(IDX)                                                        \
	do {                                                                                 \
		bn_read_bin(k, pseudo_random_bytes + IDX * len_per_elm, len_per_elm);            \
		fp_prime_conv(t, k);                                                             \
	} while (0)

#define EP_MAP_APPLY_MAP(PT)                                                             \
	do {                                                                                 \
		/* check sign of t */                                                            \
		fp_prime_back(k, t);                                                             \
		neg = bn_cmp(k, pm1o2);                                                          \
		/* convert */                                                                    \
		map_fn(PT, t);                                                                   \
		/* fix sign of y */                                                              \
		fp_prime_back(k, PT->y);                                                         \
		fp_neg(t, PT->y);                                                                \
		dv_copy_cond(PT->y, t, RLC_FP_DIGS, neg != bn_cmp(k, pm1o2));                    \
	} while (0)

		/* first map invocation */
		EP_MAP_CONVERT_BYTES(0);
		EP_MAP_APPLY_MAP(p);

		/* second map invocation */
		EP_MAP_CONVERT_BYTES(1);
		EP_MAP_APPLY_MAP(q);

#undef EP_MAP_CONVERT_BYTES
#undef EP_MAP_APPLY_MAP

		/* sum the result */
		ep_add(p, p, q);
		ep_norm(p, p);

		/* clear cofactor */
		switch (ep_curve_is_pairf()) {
			case EP_BN:
				/* h = 1 */
				break;
			case EP_B12:
				/* multiply by 1-x (x the BLS parameter) to get the correct group. */
				/* XXX(rsw) is this guaranteed to work? It could fail if one
				 *          of the prime-squared subgroups is cyclic, but
				 *          maybe there's an argument that this is never the case...
				 */
				fp_prime_get_par(k);
				bn_neg(k, k);
				bn_add_dig(k, k, 1);
				if (bn_bits(k) < RLC_DIG) {
					ep_mul_dig(p, p, k->dp[0]);
				} else {
					ep_mul(p, p, k);
				}
				break;
			default:
				/* multiply by cofactor to get the correct group. */
				ep_curve_get_cof(k);
				if (bn_bits(k) < RLC_DIG) {
					ep_mul_dig(p, p, k->dp[0]);
				} else {
					ep_mul_basic(p, p, k);
				}
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(k);
		bn_free(pm1o2);
		fp_free(t);
		ep_free(q);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep_map(ep_t p, const uint8_t *msg, int len) {
	ep_map_impl(p, msg, len, (const uint8_t *)"RELIC", 5);
}
