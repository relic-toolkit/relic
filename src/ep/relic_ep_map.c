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

#undef EP_MAP_copy_sec

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
	fp_t a, b, c, d, e, f, t, u, v, w, y, x1, y1, z1, den[3];
	ctx_t *ctx = core_get();
	bn_t k;

	if (ep_curve_is_super()) {
		RLC_FREE(pseudo_random_bytes); 
		RLC_THROW(ERR_NO_CONFIG);
		return;
	}

	if (ctx->mod18 % 3 == 2) {
		RLC_FREE(pseudo_random_bytes); 
		RLC_THROW(ERR_NO_CONFIG);
		return;
	}

	bn_null(k);
	fp_null(a);
	fp_null(b);
	fp_null(c);
	fp_null(d);
	fp_null(e);
	fp_null(f);
	fp_null(t);
	fp_null(u);
	fp_null(v);
	fp_null(w);
	fp_null(y);
	fp_null(x1);
	fp_null(y1);
	fp_null(z1);
	fp_null(den[0]);
	fp_null(den[1]);
	fp_null(den[2]);

	RLC_TRY {
		bn_new(k);
		fp_new(a);
		fp_new(b);
		fp_new(c);
		fp_new(d);
		fp_new(e);
		fp_new(f);
		fp_new(t);
		fp_new(u);
		fp_new(v);
		fp_new(w);
		fp_new(y);
		fp_new(x1);
		fp_new(y1);
		fp_new(z1);
		fp_new(den[0]);
		fp_new(den[1]);
		fp_new(den[2]);

		md_xmd(pseudo_random_bytes, 2 * len_per_elm + 1, msg, len,
				(const uint8_t *)"RELIC", 5);

		bn_read_bin(k, pseudo_random_bytes, len_per_elm);
		fp_prime_conv(u, k);
		bn_read_bin(k, pseudo_random_bytes + len_per_elm, len_per_elm);
		fp_prime_conv(t, k);
		s = pseudo_random_bytes[2 * len_per_elm] & 1;

		if (ep_curve_opt_b() == RLC_ZERO) {
			fp_sqr(a, u);
			fp_sqr(b, a);
			fp_mul(c, b, a);
			if (ep_curve_opt_a() == RLC_ONE) {
				fp_add_dig(c, c, 64);
			} else {
				fp_dbl(f, ep_curve_get_a());
				fp_dbl(f, f);
				fp_sqr(e, f);
				fp_mul(e, e, f);
				fp_add(c, c, e);
			}
			fp_sqr(d, t);

			fp_mul(v, a, d);
			fp_mul(v, v, u);
			fp_mul_dig(v, v, 24);
			fp_mul(v, v, ctx->ep_map_c[4]);

			fp_sub_dig(p->x, ctx->ep_map_c[4], 1);
			fp_hlv(p->x, p->x);

			fp_sqr(w, b);
			fp_mul(y, v, a);
			if (ep_curve_opt_a() == RLC_ONE) {
				fp_dbl(t, c);
				fp_dbl(t, t);
			} else {
				fp_mul(t, f, c);
			}
			fp_add(y, y, t);
			fp_mul(y, y, p->x);

			fp_add(den[0], c, v);
			fp_mul(den[0], den[0], u);
			fp_mul(den[0], den[0], ctx->ep_map_c[4]);
			fp_mul(den[0], den[0], p->x);
			fp_dbl(den[0], den[0]);
			fp_neg(den[0], den[0]);
			fp_mul(den[1], den[0], p->x);
			if (ep_curve_opt_a() == RLC_ONE) {
				fp_sub_dig(den[2], a, 4);
			} else {
				fp_sub(den[2], a, f);
			}
			fp_sqr(den[2], den[2]);
			fp_mul_dig(den[2], den[2], 216);
			fp_dbl(den[2], den[2]);
			fp_neg(den[2], den[2]);
			fp_mul(den[2], den[2], b);
			fp_mul(den[2], den[2], d);

			if (fp_is_zero(den[0]) || fp_is_zero(den[1]) || fp_is_zero(den[2])) {
				ep_set_infty(p);
			} else {
				fp_inv_sim(den, den, 3);
				if (ep_curve_opt_a() == RLC_ONE) {
					fp_dbl(a, a);
					fp_dbl(a, a);
					fp_dbl(a, a);
					fp_dbl(a, a);
					fp_add(y1, a, v);
					fp_dbl(y1, y1);
					fp_dbl(y1, y1);
				} else {
					fp_mul(y1, f, v);
					fp_mul(u, a, e);
					fp_add(y1, y1, u);
				}
				fp_add(y1, y1, w);
				fp_mul(z1, y, p->x);
				fp_add(x1, y1, z1);
				fp_add(y1, y1, y);

				if (ep_curve_opt_a() == RLC_ONE) {
					fp_dbl(e, b);
					fp_dbl(e, e);
					fp_add(z1, a, e);
				} else {
					fp_mul(z1, f, a);
					fp_add(z1, z1, b);
					fp_mul(z1, z1, f);
				}
				fp_dbl(t, z1);
				fp_add(z1, z1, t);
				fp_sub(z1, c, z1);
				fp_sub(z1, z1, v);
				fp_mul(z1, z1, v);
				if (ep_curve_opt_a() == RLC_ONE) {
					fp_dbl(a, a);
					fp_dbl(a, a);
					fp_dbl(a, a);
					fp_set_dig(d, 64);
					fp_sqr(d, d);
				} else {
					fp_dbl(a, u);
					fp_sqr(d, e);
				}
				fp_add(a, a, w);
				fp_mul(u, a, b);
				fp_sub(z1, u, z1);
				fp_add(z1, z1, d);

				fp_mul(x1, x1, den[0]);
				fp_mul(y1, y1, den[1]);
				fp_mul(z1, z1, den[2]);

				ep_rhs(t, x1);
				ep_rhs(u, y1);
				ep_rhs(v, z1);

				int c2 = fp_is_sqr(u);
				int c3 = fp_is_sqr(v);

				fp_copy_sec(t, u, c2);
				fp_copy_sec(x1, y1, c2);
				fp_copy_sec(t, v, c3);
				fp_copy_sec(x1, z1, c3);

				if (!fp_srt(t, t)) {
					RLC_THROW(ERR_NO_VALID);
				}
				fp_neg(u, t);
				fp_copy_sec(t, u, fp_is_even(t) ^ s);

				fp_copy(p->x, x1);
				fp_copy(p->y, t);
				fp_set_dig(p->z, 1);
				p->coord = BASIC;
			}
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

					dv_swap_sec(x1, y1, RLC_FP_DIGS, c2);
					dv_swap_sec(t, u, RLC_FP_DIGS, c2);
					dv_swap_sec(x1, z1, RLC_FP_DIGS, c3);
					dv_swap_sec(t, v, RLC_FP_DIGS, c3);

					if (!fp_srt(t, t)) {
						RLC_THROW(ERR_NO_VALID);
					}
					fp_neg(u, t);
					dv_swap_sec(t, u, RLC_FP_DIGS, fp_is_even(t) ^ s);

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
		fp_free(d);
		fp_free(e);
		fp_free(f);
		fp_free(t);
		fp_free(u);
		fp_free(v);
		fp_free(w);
		fp_free(y);
		fp_free(x1);
		fp_free(y1);
		fp_free(z1);
		fp_free(den[0]);
		fp_free(den[1]);
		fp_free(den[2]);
		RLC_FREE(pseudo_random_bytes);
	}
}

#endif
