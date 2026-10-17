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
 * Implementation of hashing to a prime elliptic curve over a quadratic
 * extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"
#include "relic_md.h"
#include "relic_ep_map_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Evaluate a polynomial represented by its coefficients using Horner's rule.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the input value.
 * @param[in] coeffs		- the vector of coefficients in the polynomial.
 * @param[in] len			- the degree of the polynomial.
 */
TMPL_EP_MAP_HORNER(fp2, fp2_t)

/**
 * Generic isogeny map evaluation for use with SSWU map.
 */
TMPL_EP_MAP_ISOGENY_MAP(ep2, fp2, iso2)

/**
 * Simplified SWU mapping.
 */
TMPL_EP_MAP_SSWU(ep2, fp2, fp_t)

/**
 * Shallue--van de Woestijne map.
 */
TMPL_EP_MAP_SVDW(ep2, fp2, fp_t)

/**
 * Maps a byte array to a point in an elliptic curve over a quadratic extension
 * using an explicit domain separation tag.
 *
 * @param[out] p			- the result.
 * @param[in] msg			- the byte array to map.
 * @param[in] len			- the array length in bytes.
 * @param[in] dst			- the domain separatoin tag.
 * @param[in] dst_len		- the domain separation tag length in bytes.
 */
static void ep2_map_from_field(ep2_t p, const uint8_t *r, size_t len) {
	bn_t k;
	fp2_t t;
	ep2_t q;
	int neg, sy;
	/* enough space for two extension field elements plus extra bytes for uniformity */
	const size_t lpe = (FP_PRIME + ep_param_level() + 7) / 8;

	bn_null(k);
	fp2_null(t);
	ep2_null(q);

	RLC_TRY {
		if (len != 2 * lpe) {
			RLC_THROW(ERR_NO_VALID);
		}

		bn_new(k);
		fp2_new(t);
		ep2_new(q);

		/* which hash function should we use? */
		const int abNeq0 = (ep2_curve_opt_a() != RLC_ZERO) &&
				(ep2_curve_opt_b() != RLC_ZERO);
		void (*const map_fn)(ep2_t, fp2_t) = (void (*const))
				(ep2_curve_is_ctmap() || abNeq0 ? ep2_map_sswu : ep2_map_svdw);

#define EP2_MAP_CONVERT_BYTES(IDX)											\
		do {																\
			bn_read_bin(k, r + 2 * IDX * lpe, lpe);							\
			fp_prime_conv(t[0], k);											\
			bn_read_bin(k, r + (2 * IDX + 1) * lpe, lpe);					\
			fp_prime_conv(t[1], k);											\
	    } while (0)

#define EP2_MAP_APPLY_MAP(PT)												\
		do {																\
            /* sign of t */													\
            neg = 0;														\
            TMPL_EP_MAP_SGN0(fp2, t, k, neg);								\
            /* convert */													\
            map_fn(PT, t);													\
            /* compare sign of y to sign of t; fix if necessary */			\
            sy = 0;															\
            TMPL_EP_MAP_SGN0(fp2, PT->y, k, sy);							\
            neg = neg != sy;												\
            fp2_neg(t, PT->y);												\
            fp2_copy_sec(PT->y, t, neg);									\
		} while (0)

		/* first map invocation */
		EP2_MAP_CONVERT_BYTES(0);
		EP2_MAP_APPLY_MAP(p);
		TMPL_EP_MAP_CALL_ISOMAP(ep2, p);

		/* second map invocation */
		EP2_MAP_CONVERT_BYTES(1);
		EP2_MAP_APPLY_MAP(q);
		TMPL_EP_MAP_CALL_ISOMAP(ep2, q);

		/* XXX(rsw) could add p and q and then apply isomap,
		 * but need ep_add to support addition on isogeny curves */

#undef EP2_MAP_CONVERT_BYTES
#undef EP2_MAP_APPLY_MAP

		/* sum the result */
		ep2_add(p, p, q);
		ep2_norm(p, p);
		ep2_mul_cof(p, p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp2_free(t);
		ep2_free(q);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep2_map_basic(ep2_t p, const uint8_t *msg, size_t len) {
	bn_t x;
	fp2_t t0;
	uint8_t digest[RLC_MD_LEN];

	bn_null(x);
	fp2_null(t0);

	RLC_TRY {
		bn_new(x);
		fp2_new(t0);

		md_map(digest, msg, len);
		bn_read_bin(x, digest, RLC_MIN(RLC_FP_BYTES, RLC_MD_LEN));

		fp2_zero(p->x);
		fp_prime_conv(p->x[0], x);
		fp2_set_dig(p->z, 1);

		while (1) {
			ep2_rhs(t0, p->x);

			if (fp2_is_sqr(t0) == 1) {
				fp2_srt(p->y, t0);
				p->coord = EC_AFFIN;
				break;
			}

			fp2_add_dig(p->x, p->x, 1);
		}

		ep2_mul_cof(p, p);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(x);
		fp2_free(t0);
	}
}

void ep2_map_sswum(ep2_t p, const uint8_t *msg, size_t len) {
	ep2_map_dst(p, msg, len, (const uint8_t *)RLC_DSTAG, strlen(RLC_DSTAG));
}

void ep2_map_dst(ep2_t p, const uint8_t *msg, size_t len, const uint8_t *dst,
		size_t dst_len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t lpe = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t *r = RLC_ALLOCA(uint8_t, 4 * lpe);

	RLC_TRY {
		if (r == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		/* XXX(rsw) See note in ep/relic_ep_map.c about using MD_MAP. */
		/* hash to a pseudorandom string using md_xmd */
		md_xmd(r, 4 * lpe, msg, len, dst, dst_len);
		ep2_map_from_field(p, r, 2 * lpe);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		RLC_FREE(r);
	}
}

TMPL_EP_MAP_AB(ep2, fp2, ep2_map_swift);
