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
	fp_t c, t, u, v, w, y, x1, y1, z1;
	ctx_t *ctx = core_get();
	bn_t k, n;
	dig_t r;

	bn_null(k);
	bn_null(n);
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
		bn_new(n);
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

		if (ep_curve_opt_b() == RLC_ZERO) {
			/* This is the approach due to Koshelev introduced in
			 * https://eprint.iacr.org/2021/1604.pdf */
			fp_set_dig(c, -fp_prime_get_qnr());
			fp_neg(c, c);
			fp_print(u);
			fp_print(t);

			/* u = t0, t = t1, v = t0^4, y = t1^4, w = c^2, z1 = 8*a^2*c. */
			fp_sqr(v, u);
			fp_sqr(v, v);
			fp_sqr(y, t);
			fp_sqr(y, y);
			fp_sqr(w, c);
			fp_sqr(z1, ep_curve_get_a());
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
			fp_mul(z1, z1, ep_curve_get_a());
			fp_dbl(z1, z1);
			/* v = num2 = c^4*t0^8 - 2*c^2t0^4t1^4 + t1^8 - 16*a^3*c^2*/
			fp_sub(v, y1, x1);
			fp_add(v, v, y);
			fp_sub(v, v, z1);
			/* w = num0 = t0 * ac(-3*c^4t0^8 + 2c^2*t0^4*t1^4 + t1^8 + 16*a^3*c^2)*/
			fp_add(w, y, z1);
			fp_add(w, w, x1);
			fp_sub(w, w, y1);
			fp_sub(w, w, y1);
			fp_sub(w, w, y1);
			fp_mul(w, w, c);
			fp_mul(w, w, u);
			fp_mul(w, w, ep_curve_get_a());
			/* z1 = num1 = t1 * ac^2(c^4t0^8 + 2c^2t0^4*t1^4 - 3^t1^8 + 16a^3c^2)*/
			fp_sub(z1, z1, y);
			fp_sub(z1, z1, y);
			fp_sub(z1, z1, y);
			fp_add(z1, z1, x1);
			fp_add(z1, z1, y1);
			fp_mul(z1, z1, t);
			fp_mul(z1, z1, c);
			fp_mul(z1, z1, c);
			fp_mul(z1, z1, ep_curve_get_a());
			/* v2 = num2/den = z1/w. */
			fp_mul(w, w, p->z);
			fp_mul(z1, z1, p->z);
			fp_mul(v, v, p->z);

			bn_read_raw(k, fp_prime_get(), RLC_FP_DIGS);
			bn_read_raw(n, fp_prime_get(), RLC_FP_DIGS);

			if ((k->dp[0] & 0xF) == 5) {
				r = 1;
				bn_mul_dig(n, n, 3);
				bn_add_dig(n, n, 1);
			} else if ((k->dp[0] & 0xF) == 13) {
				r = 3;
				bn_add_dig(n, n, 3);
			} else {
				RLC_THROW(ERR_NO_VALID);
			}
			bn_rsh(n, n, 4);
			/* Compute y1 = d = c^n. */
			fp_exp(y1, c, n);
			/* Compute x1 = f = t^3 + a*t = t(t^2 + a). */
			fp_sqr(x1, v);
			fp_add(x1, x1, ep_curve_get_a());
			fp_mul(x1, x1, v);
			/* Compute c = i = (c|p)_4*/
			bn_sub_dig(k, k, 1);
			bn_rsh(k, k, 2);
			fp_exp(c, c, k);
			/* Compute y = theta, w = theta^4. */
			fp_exp(y, x1, n);
			fp_sqr(w, y);
			fp_sqr(w, w);
			/* Compute c = i^r * f. */
			bn_set_dig(n, r);
			fp_exp(c, c, n);
			fp_mul(c, c, x1);
			fp_set_dig(p->z, 1);
			p->coord = BASIC;
			if (fp_cmp(w, x1) == RLC_EQ) {
				fp_copy(p->x, v);
				fp_sqr(p->y, y);
			} else {
				fp_neg(x1, x1);
				if (fp_cmp(w, x1) == RLC_EQ) {
					fp_copy(p->x, v);
					fp_sqr(p->y, y);
					fp_neg(z1, p->z);
					fp_srt(z1, z1);
					fp_inv(z1, z1);
					fp_mul(p->y, p->y, z1);
				} else {
					fp_mul(y, y, y1);
					fp_inv(y, y);
					if (fp_cmp(w, c) == RLC_EQ) {
						fp_mul(p->x, u, y);
						fp_mul(p->x, p->x, y);
						fp_mul(p->y, w, y);
						fp_mul(p->y, p->y, y);
						fp_mul(p->y, p->y, y);
					} else {
						fp_inv(y1, y1);
						fp_neg(c, c);
						if (fp_cmp(w, c) == RLC_EQ) {
							fp_mul(p->x, t, y);
							fp_mul(p->x, p->x, y);
							fp_mul(p->x, p->x, y1);
							fp_mul(p->x, p->x, y1);
							fp_mul(p->x, p->x, y1);
							fp_mul(p->x, p->x, y1);
							fp_mul(p->y, z1, y);
							fp_mul(p->y, p->y, y);
							fp_mul(p->y, p->y, y);
							fp_mul(p->y, p->y, y1);
							fp_mul(p->y, p->y, y1);
							fp_mul(p->y, p->y, y1);
							fp_mul(p->y, p->y, y1);
							fp_mul(p->y, p->y, y1);
							fp_mul(p->y, p->y, y1);
						} else {
							RLC_THROW(ERR_NO_VALID);
						}
					}
				}
			}
			ep_mul_cof(p, p);
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
					ep_mul_cof(p, p);
				}
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		bn_free(n);
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
