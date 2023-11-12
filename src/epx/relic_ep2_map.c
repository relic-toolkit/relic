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
TMPL_MAP_ISOGENY_MAP(ep2, fp2, iso2)
#endif /* EP_CTMAP */

/**
 * Simplified SWU mapping.
 */
#define EP2_MAP_COPY_COND(O, I, C)											\
	do {																	\
		dv_copy_cond(O[0], I[0], RLC_FP_DIGS, C);							\
		dv_copy_cond(O[1], I[1], RLC_FP_DIGS, C);							\
	} while (0)
TMPL_MAP_SSWU(ep2, fp2, fp_t, EP2_MAP_COPY_COND)

/**
 * Shallue--van de Woestijne map.
 */
TMPL_MAP_SVDW(ep2, fp2, fp_t, EP2_MAP_COPY_COND)

#undef EP2_MAP_COPY_COND

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
	int neg;
	/* enough space for two extension field elements plus extra bytes for uniformity */
	const int lpe = (FP_PRIME + ep_param_level() + 7) / 8;

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
		const void (*const map_fn)(ep2_t, fp2_t) = (void (*const))
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
            neg = fp2_sgn0(t, k);											\
            /* convert */													\
            map_fn(PT, t);													\
            /* compare sign of y to sign of t; fix if necessary */			\
            neg = neg != fp2_sgn0(PT->y, k);								\
            fp2_neg(t, PT->y);												\
            dv_copy_cond(PT->y[0], t[0], RLC_FP_DIGS, neg);					\
            dv_copy_cond(PT->y[1], t[1], RLC_FP_DIGS, neg);					\
		} while (0)

		/* first map invocation */
		EP2_MAP_CONVERT_BYTES(0);
		EP2_MAP_APPLY_MAP(p);
		TMPL_MAP_CALL_ISOMAP(ep2, p);

		/* second map invocation */
		EP2_MAP_CONVERT_BYTES(1);
		EP2_MAP_APPLY_MAP(q);
		TMPL_MAP_CALL_ISOMAP(ep2, q);

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

#if EP_MAP == BASIC || !defined(STRIP)

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
			ep2_rhs(t0, p);

			if (fp2_is_sqr(t0) == 1) {
				fp2_srt(p->y, t0);
				p->coord = BASIC;
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

#endif

#if EP_MAP == SSWUM || !defined(STRIP)

void ep2_map_sswum(ep2_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const int lpe = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t *r = RLC_ALLOCA(uint8_t, 4 * lpe);

	RLC_TRY {
		if (r == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		/* XXX(rsw) See note in ep/relic_ep_map.c about using MD_MAP. */
		/* hash to a pseudorandom string using md_xmd */
		md_xmd(r, 4 * lpe, msg, len, (const uint8_t *)"RELIC", 5);
		ep2_map_from_field(p, r, 2 * lpe);
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

void ep2_map_swift(ep2_t p, const uint8_t *msg, size_t len) {
	/* enough space for two field elements plus extra bytes for uniformity */
	const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;
	uint8_t t0z, t0, t1, sign, *r = RLC_ALLOCA(uint8_t, 4 * elm + 1);
	fp2_t t, u, v, w, y, x1, y1, z1;
	ctx_t *ctx = core_get();
	dig_t c2, c3;
	bn_t k;

	bn_null(k);
	fp2_null(t);
	fp2_null(u);
	fp2_null(v);
	fp2_null(w);
	fp2_null(y);
	fp2_null(x1);
	fp2_null(y1);
	fp2_null(z1);

	RLC_TRY {
		bn_new(k);
		fp2_new(t);
		fp2_new(u);
		fp2_new(v);
		fp2_new(w);
		fp2_new(y);
		fp2_new(x1);
		fp2_new(y1);
		fp2_new(z1);

		md_xmd(r, 4 * elm + 1, msg, len, (const uint8_t *)"RELIC", 5);

		for (int i = 0; i < 2; i++) {
			bn_read_bin(k, r, elm);
			fp_prime_conv(u[i], k);
			r += elm;
			bn_read_bin(k, r, elm);
			fp_prime_conv(t[i], k);
			r += elm;
		}
		sign = r[0] & 1;
		r -= 4 * elm;

		/* Assume that a = 0. */
		fp2_sqr(x1, u);
		fp2_mul(x1, x1, u);
		fp2_sqr(y1, t);
		fp2_add(x1, x1, ctx->ep2_b);
		fp2_sub(x1, x1, y1);
		fp2_dbl(y1, y1);
		fp2_add(y1, y1, x1);
		fp2_copy(z1, u);
		fp_mul(z1[0], z1[0], ctx->ep_map_c[4]);
		fp_mul(z1[1], z1[1], ctx->ep_map_c[4]);
		fp2_mul(x1, x1, z1);
		fp2_mul(z1, z1, t);
		fp2_dbl(z1, z1);

		fp2_dbl(y, y1);
		fp2_sqr(y, y);
		fp2_mul(v, y1, u);
		fp2_sub(v, x1, v);
		fp2_mul(v, v, z1);
		fp2_mul(w, y1, z1);
		fp2_dbl(w, w);

		if (fp2_is_zero(w)) {
			ep2_set_infty(p);
		} else {
			fp2_inv(w, w);
			fp2_mul(x1, v, w);
			fp2_add(y1, u, x1);
			fp2_neg(y1, y1);
			fp2_mul(z1, y, w);
			fp2_sqr(z1, z1);
			fp2_add(z1, z1, u);

			fp2_sqr(t, x1);
			fp2_mul(t, t, x1);
			fp2_add(t, t, ctx->ep2_b);

			fp2_sqr(u, y1);
			fp2_mul(u, u, y1);
			fp2_add(u, u, ctx->ep2_b);

			fp2_sqr(v, z1);
			fp2_mul(v, v, z1);
			fp2_add(v, v, ctx->ep2_b);

			c2 = fp2_is_sqr(u);
			c3 = fp2_is_sqr(v);

			for (int i = 0; i < 2; i++) {
				dv_swap_cond(x1[i], y1[i], RLC_FP_DIGS, c2);
				dv_swap_cond(t[i], u[i], RLC_FP_DIGS, c2);
				dv_swap_cond(x1[i], z1[i], RLC_FP_DIGS, c3);
				dv_swap_cond(t[i], v[i], RLC_FP_DIGS, c3);
			}

			if (!fp2_srt(t, t)) {
				RLC_THROW(ERR_NO_VALID);
			}

			t0z = fp_is_zero(t[0]);
			fp_prime_back(k, t[0]);
			t0 = bn_get_bit(k, 0);
			fp_prime_back(k, t[1]);
			t1 = bn_get_bit(k, 0);
			/* t[0] == 0 ? sgn0(t[1]) : sgn0(t[0]) */
			sign ^= (t0 | (t0z & t1));

			fp2_neg(u, t);
			dv_swap_cond(t[0], u[0], RLC_FP_DIGS, sign);
			dv_swap_cond(t[1], u[1], RLC_FP_DIGS, sign);

			fp2_copy(p->x, x1);
			fp2_copy(p->y, t);
			fp2_set_dig(p->z, 1);
			p->coord = BASIC;

			ep2_mul_cof(p, p);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(k);
		fp2_free(t);
		fp2_free(u);
		fp2_free(v);
		fp2_free(w);
		fp2_free(y);
		fp2_free(x1);
		fp2_free(y1);
		fp2_free(z1);
		RLC_FREE(r);
	}
}

#endif
