/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2020 RELIC Authors
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
 * @version $Id$
 * @ingroup ed
 */

#include "relic_core.h"
#include "relic_md.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

void ed_map_ell2_5mod8(ed_t p, fp_t t) {
	bn_t h;
	fp_t tv1, tv2, tv3, tv4, tv5;
	bn_null(h);
	fp_null(tv1);
	fp_null(tv2);
	fp_null(tv3);
	fp_null(tv4);
	fp_null(tv5);

	/* aliases to make code easier to read */
	ctx_t *ctx = core_get();
	dig_t *c_2exp = ctx->ed_map_c[0];
	dig_t *sqrt_M1 = ctx->ed_map_c[1];
	dig_t *sqrt_M486664 = ctx->ed_map_c[2];
	dig_t *c_486662 = ctx->ed_map_c[3];

	TRY {
		bn_new(h);
		fp_new(tv1);
		fp_new(tv2);
		fp_new(tv3);
		fp_new(tv4);
		fp_new(tv5);

		/* set h = (p - 5) / 8 */
		h->used = RLC_FP_DIGS;
		h->sign = RLC_POS;
		dv_copy(h->dp, fp_prime_get(), RLC_FP_DIGS); /* p */
		bn_sub_dig(h, h, 5);                         /* p - 5 */
		bn_rsh(h, h, 3);                             /* (p - 5) / 8 */

		/* start evaluating map */
		fp_sqr(tv1, t);
		fp_dbl(tv1, tv1);
		fp_add_dig(tv3, tv1, 1);
		fp_sqr(tv2, tv3);
		fp_mul(p->z, tv2, tv3);

		/* compute numerator of g(x1) */
		fp_sqr(tv4, c_486662);
		fp_mul(tv4, tv4, tv1);
		fp_sub(tv4, tv4, tv2);
		fp_mul(tv4, tv4, c_486662);

		/* compute divsrqt */
		fp_sqr(tv3, p->z);
		fp_sqr(tv2, tv3);
		fp_mul(tv3, tv3, p->z);
		fp_mul(tv3, tv3, tv4);
		fp_mul(tv2, tv2, tv3);
		fp_exp(tv2, tv2, h);
		fp_mul(tv2, tv2, tv3);

		/* figure out which sqrt we should keep */
		fp_mul(p->y, tv2, sqrt_M1);
		fp_sqr(p->x, tv2);
		fp_mul(p->x, p->x, p->z);
		{
			const int e1 = fp_cmp(p->x, tv4);
			dv_copy_cond(p->y, tv2, RLC_FP_DIGS, e1 == RLC_EQ);
		} /* e1 goes out of scope */

		/* compute numerator of g(x2) */
		fp_mul(tv3, tv2, t);
		fp_mul(tv3, tv3, c_2exp);
		fp_mul(tv5, tv3, sqrt_M1);

		/* figure out which sqrt we should keep */
		fp_mul(p->x, tv4, tv1);
		fp_sqr(tv2, tv3);
		fp_mul(tv2, tv2, p->z);
		{
			const int e2 = fp_cmp(p->x, tv2);
			dv_copy_cond(tv5, tv3, RLC_FP_DIGS, e2 == RLC_EQ);
		} /* e2 goes out of scope */

		/* figure out whether we wanted y1 or y2 and x1 or x2 */
		fp_sqr(tv2, p->y);
		fp_mul(tv2, tv2, p->z);
		{
			const int e3 = fp_cmp(tv2, tv4);
			fp_set_dig(p->x, 1);
			dv_copy_cond(p->x, tv1, RLC_FP_DIGS, e3 != RLC_EQ);
			fp_mul(p->x, p->x, c_486662);
			fp_neg(p->x, p->x);
			dv_copy_cond(p->y, tv5, RLC_FP_DIGS, e3 != RLC_EQ);
		} /* e3 goes out of scope */
		fp_add_dig(p->z, tv1, 1);

		/* fix sign of y */
		fp_neg(tv2, p->y);
		fp_prime_back(h, t);
		const int neg_t = bn_get_bit(h, 0);
		fp_prime_back(h, p->y);
		dv_copy_cond(p->y, tv2, RLC_FP_DIGS, neg_t != bn_get_bit(h, 0));

		/* convert to an Edwards point */
		/* tmp1 = xnumerator = sqrt_M486664 * x */
		fp_mul(tv1, p->x, sqrt_M486664); /* xn = sqrt(-486664) * x */
		fp_mul(tv2, p->y, p->z);         /* xd = y * z */
		fp_sub(tv3, p->x, p->z);         /* yn = x - z */
		fp_add(tv4, p->x, p->z);         /* yd = x + z */

		fp_mul(p->z, tv2, tv4);
		fp_mul(p->x, tv1, tv4);
		fp_mul(p->y, tv2, tv3);
		{
			/* exceptional case: either denominator == 0 */
			const int e4 = fp_is_zero(p->z);
			fp_set_dig(tv5, 1);
			dv_copy_cond(p->x, p->z, RLC_FP_DIGS, e4 == RLC_EQ);
			dv_copy_cond(p->y, tv5, RLC_FP_DIGS, e4 == RLC_EQ);
			dv_copy_cond(p->z, tv5, RLC_FP_DIGS, e4 == RLC_EQ);
		} /* e4 goes out of scope */

		/* clear denominator if necessary */
#if EP_ADD == EXTND || EP_ADD == PROJC
		p->norm = 0;
#if EP_ADD == EXTND
		fp_mul(p->t, p->x, p->y);
#endif /* EP_ADD == EXTND */
#else  /* EP_ADD == BASIC */
		fp_inv(tv1, p->z);
		fp_mul(p->x, p->x, tv1);
		fp_mul(p->y, p->y, tv1);
		fp_set_dig(p->z, 1);
		p->norm = 1;
#endif /* EP_ADD */
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT)
	}
	FINALLY {
		bn_free(h);
		fp_free(tv1);
		fp_free(tv2);
		fp_free(tv3);
		fp_free(tv4);
		fp_free(tv5);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ed_map(ed_t p, const uint8_t *msg, int len) {
	bn_t h;
	fp_t t, u, v;
	uint8_t digest[RLC_MD_LEN];

	bn_null(h);
	fp_null(t);
	fp_null(u);
	fp_null(v);

	RLC_TRY {
		bn_new(h);
		fp_new(t);
		fp_new(u);
		fp_new(v);

		md_map(digest, msg, len);
		bn_read_bin(h, digest, RLC_MIN(RLC_FP_BYTES, RLC_MD_LEN));

		fp_prime_conv(p->y, h);
		fp_set_dig(p->z, 1);

		/* Make e = p. */
		h->used = RLC_FP_DIGS;
		dv_copy(h->dp, fp_prime_get(), RLC_FP_DIGS);

		/* Compute a^((p - 5)/8). */
		bn_sub_dig(h, h, 5);
		bn_rsh(h, h, 3);

		/* Decode using Elligator 2. */
		while (1) {
			/* u = y^2 - 1, v = d * y^2 + 1. */
			fp_sqr(u, p->y);
			fp_mul(v, u, core_get()->ed_d);
			fp_sub_dig(u, u, 1);
			fp_add_dig(v, v, 1);

			/* t = v^3, x = uv^7. */
			fp_sqr(t, v);
			fp_mul(t, t, v);
			fp_sqr(p->x, t);
			fp_mul(p->x, p->x, v);
			fp_mul(p->x, p->x, u);

			/* x = uv^3 * (uv^7)^((p - 5)/8). */
			fp_exp(p->x, p->x, h);
			fp_mul(p->x, p->x, t);
			fp_mul(p->x, p->x, u);

			/* Check if vx^2 == u. */
			fp_sqr(t, p->x);
			fp_mul(t, t, v);

			if (fp_cmp(t, u) != RLC_EQ) {
				fp_neg(u, u);
				/* Check if vx^2 == -u. */
				if (fp_cmp(t, u) != RLC_EQ) {
					fp_add_dig(p->y, p->y, 1);
				} else {
					fp_mul(p->x, p->x, core_get()->srm1);
					break;
				}
			} else {
				break;
			}
		}

		/* By Elligator convention. */
		if (p->x[RLC_FP_DIGS - 1] >> (RLC_DIG - 1) == 1) {
			fp_neg(p->x, p->x);
		}

		/* Multiply by cofactor. */
		ed_dbl(p, p);
		ed_dbl(p, p);
		ed_dbl(p, p);
		ed_norm(p, p);

#if ED_ADD == EXTND
		fp_mul(p->t, p->x, p->y);
#endif
		p->coord = BASIC;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(h);
		fp_free(t);
		fp_free(u);
		fp_free(v);
	}
}
