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
static void ep_map_sswu(ep_t p, const fp_t t) {
	fp_t t0, t1, t2, t3;
	ctx_t *ctx = core_get();
	dig_t *mBoverA = ctx->ep_map_c[0];
	dig_t *a = ctx->ep_map_c[2];
	dig_t *b = ctx->ep_map_c[3];
	dig_t *u = ctx->ep_map_u;

	fp_null(t0);
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);

	TRY {
		fp_new(t0);
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);

		/* start computing the map */
		fp_sqr(t0, t);
		fp_mul(t0, t0, u);  /* t0 = u * t^2 */
		fp_sqr(t1, t0);     /* t1 = u^2 * t^4 */
		fp_add(t2, t1, t0); /* t2 = u^2 * t^4 + u * t^2 */

		/* handle the exceptional cases */
		/* XXX(rsw) should be done projectively */
		{
			const int e1 = fp_is_zero(t2);
			fp_neg(t3, u);                              /* t3 = -u */
			dv_copy_cond(t2, t3, RLC_FP_DIGS, e1);      /* exceptional case: -u instead of u^2t^4 + ut^2 */
			fp_inv(t2, t2);                             /* t2 = -1/u or 1/(u^2 * t^4 + u*t^2) */
			fp_add_dig(t3, t2, 1);                      /* t3 = 1 + t2 */
			dv_copy_cond(t2, t3, RLC_FP_DIGS, e1 == 0); /* only add 1 if t2 != -1/u */
		}
		/* e1 goes out of scope */

		/* compute x1, g(x1) */
		fp_mul(p->x, t2, mBoverA); /* p->x = -B / A * (1 + 1 / (u^2 * t^4 + u * t^2)) */
		fp_sqr(p->y, p->x);        /* x^2 */
		fp_add(p->y, p->y, a);     /* x^2 + a */
		fp_mul(p->y, p->y, p->x);  /* x^3 + a x */
		fp_add(p->y, p->y, b);     /* x^3 + a x + b */

		/* compute x2, g(x2) */
		fp_mul(t2, t0, p->x); /* t2 = u * t^2 * x1 */
		fp_mul(t1, t0, t1);   /* t1 = u^3 * t^6 */
		fp_mul(t3, t1, p->y); /* t5 = g(t2) = u^3 * t^6 * g(p->x) */

		/* XXX(rsw)
		 * This should be done in constant time and without computing 2 sqrts.
		 * Avoiding a second sqrt relies on knowing the 2-adicity of the modulus.
		 */
		if (!fp_srt(p->y, p->y)) {
			/* try x2, g(x2) */
			fp_copy(p->x, t2);
			if (!fp_srt(p->y, t3)) {
				THROW(ERR_NO_VALID);
			}
		}
		fp_set_dig(p->z, 1);
		p->norm = 1;

#ifdef EP_CTMAP
		if (ep_curve_is_ctmap()) {
			ep_iso(p, p);
		}
#endif
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp_free(t0);
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
	}
}

/**
 * Shallue--van de Woestijne map, based on the definition from
 * draft-irtf-cfrg-hash-to-curve-06, Section 6.6.1
 */
static void ep_map_svdw(ep_t p, const fp_t t) {
	fp_t t1, t2, t3, t4;
	fp_null(t1);
	fp_null(t2);
	fp_null(t3);
	fp_null(t4);

	TRY {
		fp_new(t1);
		fp_new(t2);
		fp_new(t3);
		fp_new(t4);

		ctx_t *ctx = core_get();
		dig_t *gU = ctx->ep_map_c[0];
		dig_t *mUover2 = ctx->ep_map_c[1];
		dig_t *c3 = ctx->ep_map_c[2];
		dig_t *c4 = ctx->ep_map_c[3];
		dig_t *u = ctx->ep_map_u;

		/* start computing the map */
		fp_sqr(t1, t);
		fp_mul(t1, t1, gU);
		fp_add_dig(t2, t1, 1); /* 1 + t^2 * g(u) */
		fp_sub_dig(t1, t1, 1);
		fp_neg(t1, t1);     /* 1 - t^2 * g(u) */
		fp_mul(t3, t1, t2); /* (1 + t^2 * g(u)) * (1 - t^2 * g(u)) */

		/* handle exceptional case */
		{
			/* compute inv0(t3), i.e., 0 if t3 == 0, 1/t3 otherwise */
			const int e0 = fp_is_zero(t3);
			dv_copy_cond(t3, gU, RLC_FP_DIGS, e0); /* g(u) is guaranteed to be nonzero */
			fp_inv(t3, t3);
			fp_zero(t4);
			dv_copy_cond(t3, t4, RLC_FP_DIGS, e0);
		}
		/* e0 goes out of scope */
		fp_mul(t4, t, t1);
		fp_mul(t4, t4, t3);
		fp_mul(t4, t4, c3);

		/* XXX(rsw) this should be constant time */
		/* compute x1 and g(x1) */
		fp_sub(p->x, mUover2, t4);
		ep_rhs(p->y, p);
		if (!fp_srt(p->y, p->y)) {
			/* compute x2 and g(x2) */
			fp_add(p->x, mUover2, t4);
			ep_rhs(p->y, p);
			if (!fp_srt(p->y, p->y)) {
				/* compute x3 and g(x3) */
				fp_sqr(p->x, t2);
				fp_mul(p->x, p->x, t3);
				fp_sqr(p->x, p->x);
				fp_mul(p->x, p->x, c4);
				fp_add(p->x, p->x, u);
				ep_rhs(p->y, p);
				if (!fp_srt(p->y, p->y)) {
					THROW(ERR_NO_VALID);
				}
			}
		}
		fp_set_dig(p->z, 1);
		p->norm = 1;
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT)
	}
	FINALLY {
		fp_free(t1);
		fp_free(t2);
		fp_free(t3);
		fp_free(t4);
	}
}

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
		void (*const map_fn)(ep_t, const fp_t) = (ep_curve_is_ctmap() || abNeq0) ? ep_map_sswu : ep_map_svdw;

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
