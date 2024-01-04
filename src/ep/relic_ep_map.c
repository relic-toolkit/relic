/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2010 RELIC Authors
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
TMPL_MAP_HORNER(fp, fp_st);

/**
 * Generic isogeny map evaluation for use with SSWU map.
 */
TMPL_MAP_ISOGENY_MAP(ep, fp, iso);

#endif /* EP_CTMAP */

#define EP_MAP_COPY_COND(O, I, C) dv_copy_cond(O, I, RLC_FP_DIGS, C)
/**
 * Simplified SWU mapping from Section 4 of
 * "Fast and simple constant-time hashing to the BLS12-381 Elliptic Curve"
 */
TMPL_MAP_SSWU(ep, fp, dig_t, EP_MAP_COPY_COND);

/**
 * Shallue--van de Woestijne map, based on the definition from
 * draft-irtf-cfrg-hash-to-curve-06, Section 6.6.1
 */
TMPL_MAP_SVDW(ep, fp, dig_t, EP_MAP_COPY_COND);

#undef EP_MAP_COPY_COND

/**
 * Maps an array of uniformly random bytes to a point in a prime elliptic
 * curve.
 * That array is expected to have a length suitable for two field elements plus
 * extra bytes for uniformity.
  *
 * @param[out] p			- the result.
 * @param[in] uniform_bytes	- the array of uniform bytes to map.
 * @param[in] len			- the array length in bytes.
 * @param[in] map_fn		- the mapping function.
 */
static void ep_map_from_field(ep_t p, const uint8_t *uniform_bytes, size_t len,
		const void (*const map_fn)(ep_t, const fp_t)) {
	bn_t k;
	fp_t t;
	ep_t q;
	int neg;
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t len_per_elm = (FP_PRIME + ep_param_level() + 7) / 8;

	bn_null(k);
	fp_null(t);
	ep_null(q);

	RLC_TRY {
		if (len != 2 * len_per_elm) {
			RLC_THROW(ERR_NO_VALID);
		}

		bn_new(k);
		fp_new(t);
		ep_new(q);

#define EP_MAP_CONVERT_BYTES(IDX)											\
    do {																	\
		bn_read_bin(k, uniform_bytes + IDX * len_per_elm, len_per_elm);		\
		fp_prime_conv(t, k);												\
    } while (0)

#define EP_MAP_APPLY_MAP(PT)												\
    do {																	\
		/* check sign of t */												\
		neg = fp_is_even(t);												\
		/* convert */														\
		map_fn(PT, t);														\
		/* compare sign of y and sign of t; fix if necessary */				\
		neg = neg != fp_is_even(PT->y);										\
		fp_neg(t, PT->y);													\
		dv_copy_cond(PT->y, t, RLC_FP_DIGS, neg);							\
    } while (0)

		/* first map invocation */
		EP_MAP_CONVERT_BYTES(0);
		EP_MAP_APPLY_MAP(p);
		TMPL_MAP_CALL_ISOMAP(ep, p);

		/* second map invocation */
		EP_MAP_CONVERT_BYTES(1);
		EP_MAP_APPLY_MAP(q);
		TMPL_MAP_CALL_ISOMAP(ep, q);

		/* XXX(rsw) could add p and q and then apply isomap,
		 * but need ep_add to support addition on isogeny curves */

#undef EP_MAP_CONVERT_BYTES
#undef EP_MAP_APPLY_MAP

		/* sum the result */
		ep_add(p, p, q);
		ep_norm(p, p);
		ep_mul_cof(p, p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp_free(t);
		ep_free(q);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_MAP == BASIC || !defined(STRIP)

void ep_map_basic(ep_t p, const uint8_t *msg, size_t len) {
	bn_t x;
	fp_t t0;
	uint8_t digest[RLC_MD_LEN];

	bn_null(x);
	fp_null(t0);

	RLC_TRY {
		bn_new(x);
		fp_new(t0);

		md_map(digest, msg, len);
		bn_read_bin(x, digest, RLC_MIN(RLC_FP_BYTES, RLC_MD_LEN));

		fp_zero(p->x);
		fp_prime_conv(p->x, x);
		fp_set_dig(p->z, 1);

		while (1) {
			ep_rhs(t0, p);

			if (fp_smb(t0) == 1) {
				fp_srt(p->y, t0);
				p->coord = BASIC;
				break;
			}

			fp_add_dig(p->x, p->x, 1);
		}

		ep_mul_cof(p, p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		fp_free(t0);
	}
}

#endif

#if EP_MAP == SSWUM || !defined(STRIP)

void ep_map_sswum(ep_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t *r = RLC_ALLOCA(uint8_t, 2 * elm);

	RLC_TRY {
		/* for hash_to_field, need to hash to a pseudorandom string */
		/* XXX(rsw) the below assumes that we want to use MD_MAP for hashing.
		 *          Consider making the hash function a per-curve option!
		 */
		md_xmd(r, 2 * elm, msg, len, (const uint8_t *)"RELIC", 5);
		/* figure out which hash function to use */
		const int abNeq0 = (ep_curve_opt_a() != RLC_ZERO) &&
				(ep_curve_opt_b() != RLC_ZERO);
		const void (*const map_fn)(ep_t, const fp_t) = (void (*const))
				(ep_curve_is_ctmap() || abNeq0 ? ep_map_sswu : ep_map_svdw);
		ep_map_from_field(p, r, 2 * elm, map_fn);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		RLC_FREE(r);
	}
}

#endif

#if EP_MAP == SWIFT || !defined(STRIP)

void ep_map_swift(ep_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t len_per_elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t s, *pseudo_random_bytes = RLC_ALLOCA(uint8_t, 2 * len_per_elm + 1);
	fp_t a, b, c, t, u, v, w, y, x1, y1, z1;
	ctx_t *ctx = core_get();
	bn_t k;

	bn_null(k);
	fp_null(a);
	fp_null(b);
	fp_null(c);
	fp_null(t);
	fp_null(u);
	fp_null(v);
	fp_null(w);
	fp_null(y);
	fp_null(x1);
	fp_null(y1);
	fp_null(z1);

	RLC_TRY {
		bn_new(k);
		fp_new(a);
		fp_new(b);
		fp_new(c);
		fp_new(t);
		fp_new(u);
		fp_new(v);
		fp_new(w);
		fp_new(y);
		fp_new(x1);
		fp_new(y1);
		fp_new(z1);

		md_xmd(pseudo_random_bytes, 2 * len_per_elm + 1, msg, len,
				(const uint8_t *)"RELIC", 5);

		bn_read_bin(k, pseudo_random_bytes, len_per_elm);
		fp_prime_conv(u, k);
		bn_read_bin(k, pseudo_random_bytes + len_per_elm, len_per_elm);
		fp_prime_conv(t, k);
		s = pseudo_random_bytes[2 * len_per_elm] & 1;

		fp_copy(a, ep_curve_get_a());

		if ((ep_curve_opt_b() == RLC_ZERO) && (ctx->mod8 == 1)) {
			/* This is the approach due to Koshelev introduced in
			 * https://eprint.iacr.org/2021/1034.pdf */
			if (fp_is_sqr(a)) {
				/* Compute t^2 = 3c*sqrt(a)*(2c^3*x^6 - 3*c^2*x^4 - 3*c*x^2 + 2).*/
				/* Compute w = 3*c. */
				fp_set_dig(c, -fp_prime_get_qnr());
				fp_neg(c, c);
				fp_dbl(w, c);
				fp_add(w, w, c);

				/* Compute x^2, x^4 and x^6 in sequence. */
				fp_sqr(z1, u);
				fp_sqr(y1, z1);
				fp_mul(t, z1, y1);

				fp_dbl(t, t);
				fp_mul(t, t, c);
				fp_mul(t, t, c);
				fp_mul(t, t, c);

				fp_mul(v, y1, c);
				fp_mul(v, v, w);
				fp_sub(t, t, v);

				/* v = -3*c*x^2. */
				fp_mul(v, w, z1);
				fp_neg(v, v);
				fp_add(t, t, v);
				fp_add_dig(t, t, 2);

				/* Assume a = 1 for simplicitly. */
				fp_mul(t, t, w);
				fp_mul(t, t, ctx->ep_map_c[6]);
				dig_t c1 = fp_is_sqr(t);
				/* If t is not square, compute u = 1/(uc), t = sqrt(t/c)/(c*u^3)*/
				fp_inv(v, c);
				fp_inv(x1, u);
				fp_mul(y1, t, v);
				/* If t is a square, extract its square root. */
				dv_copy_cond(t, y1, RLC_FP_DIGS, !c1);
				fp_srt(t, t);
				fp_mul(y1, t, v);
				fp_sqr(y, x1);
				fp_mul(y, y, x1);
				fp_mul(y1, y1, y);
				fp_mul(x1, x1, v);
				dv_copy_cond(u, x1, RLC_FP_DIGS, !c1);
				dv_copy_cond(t, y1, RLC_FP_DIGS, !c1);

				/* Compute x = sqrt(a)*(c*x^2 - 2)/(-3*c*x^2). */
				fp_sqr(z1, u);
				fp_mul(v, w, z1);
				fp_neg(v, v);
				fp_inv(v, v);
				fp_mul(p->x, z1, c);
				fp_sub_dig(p->x, p->x, 2);
				fp_mul(p->x, p->x, v);
				fp_mul(p->x, p->x, ctx->ep_map_c[6]);

				/* Compute y = y*2*sqrt(a)/(3^2*c^2*x^3). */
				fp_mul(z1, z1, u);
				fp_sqr(w, w);
				fp_mul(w, w, z1);
				fp_inv(w, w);
				fp_dbl(p->y, ctx->ep_map_c[6]);
				fp_mul(p->y, p->y, t);
				fp_mul(p->y, p->y, w);
				fp_set_dig(p->z, 1);
				p->coord = BASIC;
			} else {
				/* Compute c = 3*a^2, t^2 = 6a(9u^5 − 14au^3 + 3cu).*/
				fp_neg(a, a);
				fp_sqr(c, a);
				fp_dbl(t, c);
				fp_add(c, c, t);
				fp_dbl(t, c);
				fp_add(t, t, c);
				fp_mul(t, t, u);

				fp_sqr(v, u);
				fp_mul(w, v, u);
				fp_mul(x1, w, a);
				fp_mul_dig(x1, x1, 14);
				fp_sub(t, t, x1);

				fp_mul(w, w, v);
				fp_dbl(x1, w);
				fp_add(w, w, x1);
				fp_dbl(x1, w);
				fp_add(w, w, x1);
				fp_add(t, t, w);
				fp_mul(t, t, a);
				fp_dbl(t, t);
				fp_dbl(x1, t);
				fp_add(t, t, x1);
				dig_t c1 = fp_is_sqr(t);
				/* If t is not square, compute u = a/u, t = a*sqrt(a*t)/u^3*/
				fp_inv(x1, u);
				fp_mul(y1, t, a);
				/* If t is a square, extract its square root. */
				dv_copy_cond(t, y1, RLC_FP_DIGS, !c1);
				fp_srt(t, t);
				fp_mul(y1, t, a);
				fp_sqr(y, x1);
				fp_mul(y, y, x1);
				fp_mul(y1, y1, y);
				fp_mul(x1, x1, a);
				dv_copy_cond(u, x1, RLC_FP_DIGS, !c1);
				dv_copy_cond(t, y1, RLC_FP_DIGS, !c1);

				/* Compute x = 2^4*i*3*a^2*u / (3*(3*u^2 - a))^2. */
				fp_copy(y, ctx->ep_map_c[6]);
				fp_mul(c, c, u);
				fp_mul(x1, c, y);
				fp_dbl(x1, x1);
				fp_dbl(x1, x1);
				fp_dbl(x1, x1);
				fp_dbl(p->x, x1);
				fp_sqr(v, u);
				fp_dbl(z1, v);
				fp_add(z1, z1, v);
				fp_sub(z1, z1, a);
				fp_dbl(p->z, z1);
				fp_add(p->z, p->z, z1);

				/* Compute y = 3*2*(i-1)*a*(3^2*u^2 + a)*t / (3*(3*u^2 - a))^3. */
				fp_sub_dig(y, y, 1);
				fp_mul(y1, y, a);
				fp_dbl(y1, y1);
				fp_dbl(p->y, y1);
				fp_add(p->y, p->y, y1);
				fp_mul(p->y, p->y, t);
				fp_dbl(y1, v);
				fp_add(y1, y1, v);
				fp_dbl(v, y1);
				fp_add(y1, y1, v);
				fp_add(y1, y1, a);
				fp_mul(p->y, p->y, y1);

				/* Multiply by cofactor. */
				p->coord = JACOB;
				ep_norm(p, p);
			}
		} else if ((ep_curve_opt_b() == RLC_ZERO) && (ctx->mod8 != 1)) {
			/* This is the approach due to Koshelev introduced in
			 * https://eprint.iacr.org/2021/1604.pdf */
			fp_set_dig(c, -fp_prime_get_qnr());
			fp_neg(c, c);

			/* u = t0, t = t1, v = t0^4, y = t1^4, w = c^2, z1 = 8*a^2*c. */
			fp_sqr(v, u);
			fp_sqr(v, v);
			fp_sqr(y, t);
			fp_sqr(y, y);
			fp_sqr(w, c);
			fp_sqr(z1, a);
			fp_mul(z1, z1, c);
			fp_dbl(z1, z1);
			fp_dbl(z1, z1);
			fp_dbl(z1, z1);
			/* w = c^2*t0^4+t1^4, y1 = c^4*t0^8, x1 = 2*c^2*t0^4*t1^4, y = t1^8. */
			fp_mul(w, w, v);
			fp_sqr(y1, w);
			fp_mul(x1, w, y);
			fp_dbl(x1, x1);
			fp_add(w, w, y);
			fp_sqr(y, y);
			/* w = den = 8*a^2*c(c^2*t0^4 + t1^4), z1 = 16*a^3*c^2. */
			fp_mul(w, w, z1);
			fp_inv(p->z, w);
			fp_mul(z1, z1, c);
			fp_mul(z1, z1, a);
			fp_dbl(z1, z1);
			/* v = num2 = c^4*t0^8 - 2*c^2t0^4*t1^4 + t1^8 - 16*a^3*c^2*/
			fp_sub(v, y1, x1);
			fp_add(v, v, y);
			fp_sub(v, v, z1);
			/* w = num0 = t0 * ac(-3*c^4t0^8 + 2c^2*t0^4*t1^4 + t1^8 + 16*a^3*c^2)*/
			fp_add(w, y, z1);
			fp_add(w, w, x1);
			fp_sub(w, w, y1);
			fp_sub(w, w, y1);
			fp_sub(w, w, y1);
			fp_mul(w, w, u);
			fp_mul(w, w, c);
			fp_mul(w, w, a);
			/* z1 = num1 = t1 * ac^2(c^4t0^8 + 2c^2t0^4*t1^4 - 3^t1^8 + 16a^3c^2)*/
			fp_sub(z1, z1, y);
			fp_sub(z1, z1, y);
			fp_sub(z1, z1, y);
			fp_add(z1, z1, x1);
			fp_add(z1, z1, y1);
			fp_mul(z1, z1, t);
			fp_mul(z1, z1, c);
			fp_mul(z1, z1, c);
			fp_mul(z1, z1, a);
			/* v2 = num2/den = v/w. */
			fp_mul(w, w, p->z);
			fp_mul(z1, z1, p->z);
			fp_mul(v, v, p->z);
			fp_inv(v, v);

			bn_read_raw(k, fp_prime_get(), RLC_FP_DIGS);
			if ((k->dp[0] & 0xF) == 5) {
				/* n = (3p + 1)/16 */
				bn_mul_dig(k, k, 3);
				bn_add_dig(k, k, 1);
			} else if ((k->dp[0] & 0xF) == 13) {
				/* n = (p + 3)/16 */
				bn_add_dig(k, k, 3);
			} else {
				RLC_THROW(ERR_NO_VALID);
			}
			bn_rsh(k, k, 4);
			/* Compute x1 = f = (1/v2)^3 + a*(1/v2) = (1/v2)((1/v2)^2 + a). */
			fp_sqr(x1, v);
			fp_add(x1, x1, a);
			fp_mul(x1, x1, v);
			/* Compute y = theta, zp = theta^4. */
			fp_exp(y, x1, k);
			fp_sqr(p->z, y);
			fp_sqr(p->z, p->z);
			/* Perform the base change from (t0,t1) to (u0, u1). */
			fp_sqr(u, u);
			fp_mul(u, u, c);
			fp_sqr(t, t);
			fp_mul(t, t, c);
			/* Compute c = i^r * f. */
			fp_mul(c, ctx->ep_map_c[5], x1);
			fp_sqr(p->y, y);
			/* We use zp as temporary, but there is no problem with \psi. */
			int index = 0;
			fp_copy(y1, u);
			fp_copy(a, v);
			fp_sqr(b, y);
			fp_copy(p->x, a);
			fp_copy(p->y, b);
			for (int m = 0; m < 4; m++) {
				fp_mul(y1, y1, ctx->ep_map_c[5]);
				index += (fp_bits(y1) < fp_bits(u));
			}
			/* Apply consecutive endomorphisms. */
			for (int m = 0; m < 4; m++) {
				fp_neg(a, a);
				fp_mul(b, b, ep_curve_get_beta());
				dv_copy_cond(p->x, a, RLC_FP_DIGS, m < index);
				dv_copy_cond(p->y, b, RLC_FP_DIGS, m < index);
			}
			fp_neg(y1, x1);
			/* Compute 1/d * 1/theta. */
			fp_inv(y, y);
			fp_mul(y, y, ctx->ep_map_c[4]);
			dig_t c0 = fp_cmp(p->z, x1) == RLC_EQ;
			dig_t c1 = fp_cmp(p->z, y1) == RLC_EQ;
			dig_t c2 = fp_cmp(p->z, c) == RLC_EQ;
			fp_neg(c, c);
			dig_t c3 = fp_cmp(p->z, c) == RLC_EQ;
			c2 = !c0 && !c1 && c2;
			c3 = !c0 && !c1 && !c2 && c3;
			fp_copy(p->z, ctx->ep_map_c[6]);
			fp_mul(p->z, p->z, p->y);
			dv_copy_cond(p->y, p->z, RLC_FP_DIGS, c1);
			fp_copy(y1, ctx->ep_map_c[4]);
			/* Convert from projective coordinates on the surface to affine. */
			fp_mul(u, u, v);
			fp_mul(t, t, v);
			fp_sqr(v, v);
			fp_mul(w, w, v);
			fp_mul(z1, z1, v);
			/* Compute (x,y) = (x0/(d*theta)^2, y0/(d*theta)^3). */
			fp_sqr(y1, y);
			fp_mul(u, u, y1);
			fp_mul(w, w, y);
			fp_mul(w, w, y1);
			dv_copy_cond(p->x, u, RLC_FP_DIGS, c2);
			dv_copy_cond(p->y, w, RLC_FP_DIGS, c2);
			/* Compute (x,y) = (x1/(d^3*theta)^2, y1/(d^3*theta)^3). */
			fp_mul(z1, z1, y);
			fp_mul(t, t, y1);
			fp_mul(z1, z1, y1);
			fp_sqr(y, ctx->ep_map_c[4]);
			fp_mul(z1, z1, y);
			fp_sqr(y, y);
			fp_mul(t, t, y);
			fp_mul(z1, z1, y);
			dv_copy_cond(p->x, t, RLC_FP_DIGS, c3);
			dv_copy_cond(p->y, z1, RLC_FP_DIGS, c3);
			p->coord = BASIC;
			fp_set_dig(p->z, 1);
		} else {
			/* This is the SwiftEC case per se. */
			if (ep_curve_opt_a() != RLC_ZERO) {
				RLC_THROW(ERR_NO_VALID);
			} else {
				fp_sqr(x1, u);
				fp_mul(x1, x1, u);
				fp_sqr(y1, t);
				fp_add(x1, x1, ctx->ep_b);
				fp_sub(x1, x1, y1);
				fp_dbl(y1, y1);
				fp_add(y1, y1, x1);
				fp_mul(z1, u, ctx->ep_map_c[4]);
				fp_mul(x1, x1, z1);
				fp_mul(z1, z1, t);
				fp_dbl(z1, z1);

				fp_dbl(y, y1);
				fp_sqr(y, y);
				fp_mul(v, y1, u);
				fp_sub(v, x1, v);
				fp_mul(v, v, z1);
				fp_mul(w, y1, z1);
				fp_dbl(w, w);

				if (fp_is_zero(w)) {
					ep_set_infty(p);
				} else {
					fp_inv(w, w);
					fp_mul(x1, v, w);
					fp_add(y1, u, x1);
					fp_neg(y1, y1);
					fp_mul(z1, y, w);
					fp_sqr(z1, z1);
					fp_add(z1, z1, u);

					fp_sqr(t, x1);
					fp_mul(t, t, x1);
					fp_add(t, t, ep_curve_get_b());

					fp_sqr(u, y1);
					fp_mul(u, u, y1);
					fp_add(u, u, ep_curve_get_b());

					fp_sqr(v, z1);
					fp_mul(v, v, z1);
					fp_add(v, v, ep_curve_get_b());

					int c2 = fp_is_sqr(u);
					int c3 = fp_is_sqr(v);

					dv_swap_cond(x1, y1, RLC_FP_DIGS, c2);
					dv_swap_cond(t, u, RLC_FP_DIGS, c2);
					dv_swap_cond(x1, z1, RLC_FP_DIGS, c3);
					dv_swap_cond(t, v, RLC_FP_DIGS, c3);

					if (!fp_srt(t, t)) {
						RLC_THROW(ERR_NO_VALID);
					}
					fp_neg(u, t);
					dv_swap_cond(t, u, RLC_FP_DIGS, fp_is_even(t) ^ s);

					fp_copy(p->x, x1);
					fp_copy(p->y, t);
					fp_set_dig(p->z, 1);
					p->coord = BASIC;
				}
			}
		}
		/* Multiply by cofactor. */
		ep_mul_cof(p, p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp_free(a);
		fp_free(b);
		fp_free(c);
		fp_free(t);
		fp_free(u);
		fp_free(v);
		fp_free(w);
		fp_free(y);
		fp_free(x1);
		fp_free(y1);
		fp_free(z1);
		RLC_FREE(pseudo_random_bytes);
	}
}

#endif
