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
#include "relic_ep_map_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Domain separation tag.
 */
#ifndef RLC_DSTAG
#define RLC_DSTAG		RLC_STRING
#endif

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

/**
 * Simplified SWU mapping from Section 4 of
 * "Fast and simple constant-time hashing to the BLS12-381 Elliptic Curve"
 */
TMPL_MAP_SSWU(ep, fp, dig_t);

/**
 * Shallue--van de Woestijne map, based on the definition from
 * draft-irtf-cfrg-hash-to-curve-06, Section 6.6.1
 */
TMPL_MAP_SVDW(ep, fp, dig_t);

static void ep_map_basic_impl(ep_t p, const uint8_t *bytes, size_t len) {
	bn_t x;
	fp_t t0;

	bn_null(x);
	fp_null(t0);

	RLC_TRY {
		bn_new(x);
		fp_new(t0);

		bn_read_bin(x, bytes, len);
		fp_prime_conv(p->x, x);
		fp_set_dig(p->z, 1);

		while (1) {
			ep_rhs(t0, p->x);

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
static void ep_map_sswum_impl(ep_t p, const uint8_t *bytes, size_t len,
		void (*const map_fn)(ep_t, const fp_t)) {
	bn_t k;
	fp_t t;
	ep_t q;
	int neg;
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;

	bn_null(k);
	fp_null(t);
	ep_null(q);

	RLC_TRY {
		bn_new(k);
		fp_new(t);
		ep_new(q);

#define EP_MAP_CONVERT_BYTES(IDX)											\
    do {																	\
		bn_read_bin(k, bytes + IDX * elm, elm);						\
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
		dv_copy_sec(PT->y, t, RLC_FP_DIGS, neg);							\
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

static void ep_map_swift_impl(ep_t p, const uint8_t *random, size_t len) {
	fp_t h[8], t1, t2, v, w, y, x1, x2, x3, d[3];
	ctx_t *ctx = core_get();
	bn_t k;
	uint8_t s;

	bn_null(k);
	fp_null(v);
	fp_null(w);
	fp_null(y);
	fp_null(t1);
	fp_null(t2);
	fp_null(x1);
	fp_null(x2);
	fp_null(x3);
	fp_null(d[0]);
	fp_null(d[1]);
	fp_null(d[2]);

	RLC_TRY {
		bn_new(k);
		fp_new(v);
		fp_new(w);
		fp_new(y);
		fp_new(t1);
		fp_new(t2);
		fp_new(x1);
		fp_new(x2);
		fp_new(x3);
		fp_new(d[0]);
		fp_new(d[1]);
		fp_new(d[2]);
		for (size_t i = 0; i < 8; i++) {
			fp_null(h[i]);
			fp_new(h[i]);
		}

		bn_read_bin(k, random, len / 2);
		fp_prime_conv(t1, k);
		bn_read_bin(k, random + len / 2, len / 2);
		fp_prime_conv(t2, k);
		s = random[len - 1] & 1;

		if (ep_curve_opt_b() == RLC_ZERO) {
			/* h0 = t1^2, h1 = h0^2, h2 = 4a, h3 = h2^3, h4 = h0 * h1 + h3. */
			fp_sqr(h[0], t1);
			fp_sqr(h[1], h[0]);
			fp_mul(h[4], h[0], h[1]);
			if (ep_curve_opt_a() == RLC_ONE) {
				fp_add_dig(h[4], h[4], 64);
			} else {
				fp_dbl(h[2], ep_curve_get_a());
				fp_dbl(h[2], h[2]);
				fp_sqr(h[3], h[2]);
				fp_mul(h[3], h[3], h[2]);
				fp_add(h[4], h[4], h[3]);
			}
			/* h5 = t2^2, h6 = \tau * t1, h7 = 24*h0*h5*h6. */
			fp_sqr(h[5], t2);
			fp_mul(h[6], ctx->ep_map_c[4], t1);
			fp_mul(h[7], h[0], h[5]);
			fp_mul(h[7], h[7], h[6]);
			fp_mul_dig(h[7], h[7], 24);
			/* \tau = (\omega - 1)/2. */
			fp_sub_dig(p->x, ctx->ep_map_c[4], 1);
			fp_hlv(p->x, p->x);
			/* w = h9 = h1^2, v = h10 = \omega(h2h4 + h0h7). */
			fp_sqr(w, h[1]);
			fp_mul(v, h[0], h[7]);
			if (ep_curve_opt_a() == RLC_ONE) {
				fp_dbl(t1, h[4]);
				fp_dbl(t1, t1);
			} else {
				fp_mul(t1, h[2], h[4]);
			}
			fp_add(v, v, t1);
			fp_mul(v, v, p->x);

			/* d0 = -2h6\omega(h4 + h7), d1 = d0\omega. */
			fp_add(d[0], h[4], h[7]);
			fp_mul(d[0], d[0], h[6]);
			fp_mul(d[0], d[0], p->x);
			fp_dbl(d[0], d[0]);
			fp_neg(d[0], d[0]);
			fp_mul(d[1], d[0], p->x);
			if (ep_curve_opt_a() == RLC_ONE) {
				fp_sub_dig(d[2], h[0], 4);
			} else {
				fp_sub(d[2], h[0], h[2]);
			}
			/* d2 = -432*h1h5(h0 - h2)^2. */
			fp_sqr(d[2], d[2]);
			fp_mul_dig(d[2], d[2], 216);
			fp_dbl(d[2], d[2]);
			fp_neg(d[2], d[2]);
			fp_mul(d[2], d[2], h[1]);
			fp_mul(d[2], d[2], h[5]);

			if (fp_is_zero(d[0]) || fp_is_zero(d[1]) || fp_is_zero(d[2])) {
				ep_set_infty(p);
			} else {
				if (ep_curve_opt_a() == RLC_ONE) {
					/* n2 = 4(16h0 + h7). */
					fp_dbl(h[0], h[0]);
					fp_dbl(h[0], h[0]);
					fp_dbl(h[0], h[0]);
					fp_dbl(h[0], h[0]);
					fp_add(x2, h[0], h[7]);
					fp_dbl(x2, x2);
					fp_dbl(x2, x2);
				} else {
					/* n2 = h8 + h9 + h2h7 + h10. */
					fp_mul(t1, h[0], h[3]);
					fp_mul(x2, h[2], h[7]);
					fp_add(x2, x2, t1);
				}
				/* n1 = n2 + h9 + h10\omega, n2 = n1 + h10. */
				fp_add(x2, x2, w);
				fp_mul(x3, v, p->x);
				fp_add(x1, x2, x3);
				fp_add(x2, x2, v);
				/* n3 = h1(h9 + 8*16h0) + 4096 - h7(h4 - 3(4h1 + 16h0) - h7). */
				if (ep_curve_opt_a() == RLC_ONE) {
					fp_dbl(h[2], h[1]);
					fp_dbl(h[2], h[2]);
					fp_add(x3, h[2], h[0]);
				} else {
					fp_mul(x3, h[2], h[0]);
					fp_add(x3, x3, h[1]);
					fp_mul(x3, x3, h[2]);
				}
				fp_dbl(t1, x3);
				fp_add(x3, x3, t1);
				fp_sub(x3, h[4], x3);
				fp_sub(x3, x3, h[7]);
				fp_mul(x3, x3, h[7]);
				if (ep_curve_opt_a() == RLC_ONE) {
					fp_dbl(h[0], h[0]);
					fp_dbl(h[0], h[0]);
					fp_dbl(h[0], h[0]);
					fp_set_dig(t2, 64);
					fp_sqr(t2, t2);
				} else {
					fp_dbl(h[0], t1);
					fp_sqr(t2, h[3]);
				}
				fp_add(h[0], h[0], w);
				fp_mul(t1, h[0], h[1]);
				fp_sub(x3, t1, x3);
				fp_add(x3, x3, t2);

				/* Invert d0, d1 and d2 simultaneously. */
				fp_inv_sim(d, d, 3);
				fp_mul(p->x, x1, d[0]);
				fp_mul(x2, x2, d[1]);
				fp_mul(x3, x3, d[2]);
			}
		} else {
			/* This is the SwiftEC case per se. */
			if (ep_curve_opt_a() != RLC_ZERO) {
				RLC_THROW(ERR_NO_VALID);
			} else {
				/* h_0 = t1^3, h1 = t2^2, h2 = h0 + b - h1, h3 = 2h1 + h2. */
				fp_sqr(h[0], t1);
				fp_mul(h[0], h[0], t1);
				fp_sqr(h[1], t2);
				fp_add(h[2], h[0], ctx->ep_b);
				fp_sub(h[2], h[2], h[1]);
				fp_dbl(h[3], h[1]);
				fp_add(h[3], h[3], h[2]);
				/* h6 = t1\tau, v = h7 = h2h6, h8 = 2h6t2.*/
				fp_mul(x3, t1, ctx->ep_map_c[4]);
				fp_mul(v, h[2], x3);
				fp_mul(x3, x3, t2);
				fp_dbl(x3, x3);

				/* n1 = h8(h7 - t1h3), n2 = 2h3^2, d1 = 2h3h8*/
				fp_mul(x1, t1, h[3]);
				fp_sub(x1, v, x1);
				fp_mul(x1, x1, x3);
				fp_dbl(y, h[3]);
				fp_sqr(y, y);
				fp_mul(w, h[3], x3);
				fp_dbl(w, w);

				if (fp_is_zero(w)) {
					ep_set_infty(p);
				} else {
					fp_inv(w, w);
					fp_mul(p->x, x1, w);
					fp_add(x2, t1, p->x);
					fp_neg(x2, x2);
					fp_mul(x3, y, w);
					fp_sqr(x3, x3);
					fp_add(x3, x3, t1);
				}
			}
		}

		ep_rhs(p->y, p->x);
		ep_rhs(v, x2);
		ep_rhs(w, x3);

		int c2 = fp_is_sqr(v);
		int c3 = fp_is_sqr(w);

		fp_copy_sec(p->y, v, c2);
		fp_copy_sec(p->x, x2, c2);
		fp_copy_sec(p->y, w, c3);
		fp_copy_sec(p->x, x3, c3);

		if (!fp_srt(p->y, p->y)) {
			RLC_THROW(ERR_NO_VALID);
		}
		fp_neg(w, p->y);
		fp_copy_sec(p->y, w, fp_is_even(p->y) ^ s);
		fp_set_dig(p->z, 1);
		p->coord = BASIC;
		/* Multiply by cofactor. */
		ep_mul_cof(p, p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp_free(v);
		fp_free(w);
		fp_free(y);
		fp_free(t1);
		fp_free(t2);
		fp_free(x1);
		fp_free(x2);
		fp_free(x3);
		fp_free(d[0]);
		fp_free(d[1]);
		fp_free(d[2]);
		for (size_t i = 0; i < 8; i++) {
			fp_free(h[i]);
		}
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if EP_MAP == BASIC || !defined(STRIP)

void ep_map_basic(ep_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t *r = RLC_ALLOCA(uint8_t, elm);

	if (r == NULL) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	RLC_TRY {
		md_xmd(r, elm, msg, len, (const uint8_t *)RLC_DSTAG, strlen(RLC_DSTAG));
		ep_map_basic_impl(p, r, elm);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		RLC_FREE(r);
	}
}

#endif

#if EP_MAP == SSWUM || !defined(STRIP)

void ep_map_sswum(ep_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t *r = RLC_ALLOCA(uint8_t, 2 * elm);

	if (r == NULL) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	RLC_TRY {
		/* for hash_to_field, need to hash to a pseudorandom string */
		/* XXX(rsw) the below assumes that we want to use MD_MAP for hashing.
		 *          Consider making the hash function a per-curve option!
		 */
		md_xmd(r, 2 * elm, msg, len, (const uint8_t *)RLC_DSTAG,
				sizeof(RLC_DSTAG));
		/* figure out which hash function to use */
		const int abNeq0 = (ep_curve_opt_a() != RLC_ZERO) &&
				(ep_curve_opt_b() != RLC_ZERO);
		void (*const map_fn)(ep_t, const fp_t) = 
				(ep_curve_is_ctmap() || abNeq0 ? ep_map_sswu : ep_map_svdw);

		ep_map_sswum_impl(p, r, 2 * elm, map_fn);
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
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t *r = RLC_ALLOCA(uint8_t, 2 * elm + 1);
	ctx_t *ctx = core_get();

	if (ep_curve_is_super()) {
		RLC_FREE(r); 
		RLC_THROW(ERR_NO_CONFIG);
		return;
	}

	if (ctx->mod18 % 3 == 2) {
		RLC_FREE(r); 
		RLC_THROW(ERR_NO_CONFIG);
		return;
	}

	RLC_TRY {
		md_xmd(r, 2*elm + 1, msg, len, (const uint8_t *)RLC_DSTAG,
				sizeof(RLC_DSTAG));

		ep_map_swift_impl(p, r, 2 * elm + 1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		RLC_FREE(r);
	}
}

#endif

size_t ep_map_rnd_size(void) {
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;

	return 2 * elm + 1;
}

void ep_map_rnd(ep_t p, const uint8_t *uniform_bytes, size_t len) {
	/* Make sure that input is long enough for any of the hash functons. */
	if (len < ep_map_rnd_size()) {
		RLC_THROW(ERR_NO_BUFFER);
		ep_set_infty(p);
		return;
	}

#if EP_MAP == BASIC || !defined(STRIP)
	ep_map_basic_impl(p, uniform_bytes, len);
#elif EP_MAP == SSWUM || !defined(STRIP)
	ep_map_swift_impl(p, uniform_bytes, len);
#elif EP_MAP == SWIFT || !defined(STRIP)
	/* figure out which hash function to use */
	const int abNeq0 = (ep_curve_opt_a() != RLC_ZERO) &&
			(ep_curve_opt_b() != RLC_ZERO);
	void (*const map_fn)(ep_t, const fp_t) = 
			(ep_curve_is_ctmap() || abNeq0 ? ep_map_sswu : ep_map_svdw);

	ep_map_sswum_impl(p, uniform_bytes, len, map_fn);
#endif
}
