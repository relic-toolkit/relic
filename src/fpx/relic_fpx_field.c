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
 * Implementation of configuration for prime field extensions.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp2_field_get_qnr() {
	/* Override some of the results when cubic non-residue is also needed. */
#if FP_PRIME == 158 || FP_PRIME == 256
	return 4;
#elif FP_PRIME == 446
	return 16;
#else
	return core_get()->qnr2;
#endif
}

void fp2_field_init(void) {
	bn_t e;
	fp2_t t0, t1;
	ctx_t *ctx = core_get();

	bn_null(e);
	fp2_null(t0);
	fp2_null(t1);

	TRY {
		bn_new(e);
		fp2_new(t0);
		fp2_new(t1);

		/* Start by finding a quadratic/cubic non-residue. */
#ifdef FP_QNRES
		ctx->qnr2 = 1;
#else
		/* First start with u as quadratic non-residue. */
		ctx->qnr2 = 0;
		fp_zero(t0[0]);
		fp_set_dig(t0[1], 1);
		/* If it does not work, attempt (u + 2), otherwise double. */
		if (fp2_srt(t1, t0) == 1) {
			ctx->qnr2 = 2;
			fp_set_dig(t0[0], ctx->qnr2);
			while (fp2_srt(t1, t0) == 1) {
				/* Pick a power of 2 for efficiency. */
				ctx->qnr2 *= 2;
				fp_set_dig(t0[0], ctx->qnr2);
			}
		}
#endif /* !FP_QNRES */

		fp2_set_dig(t1, 1);
		fp2_mul_nor(t0, t1);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 6);
		fp2_exp(t0, t0, e);
#if ALLOC == AUTO
		fp2_copy(ctx->fp2_p[0], t0);
		fp2_sqr(ctx->fp2_p[1], ctx->fp2_p[0]);
		fp2_mul(ctx->fp2_p[2], ctx->fp2_p[1], ctx->fp2_p[0]);
		fp2_sqr(ctx->fp2_p[3], ctx->fp2_p[1]);
		fp2_mul(ctx->fp2_p[4], ctx->fp2_p[3], ctx->fp2_p[0]);
#else
		fp_copy(ctx->fp2_p[0][0], t0[0]);
		fp_copy(ctx->fp2_p[0][1], t0[1]);
		fp2_sqr(t1, t0);
		fp_copy(ctx->fp2_p[1][0], t1[0]);
		fp_copy(ctx->fp2_p[1][1], t1[1]);
		fp2_mul(t1, t1, t0);
		fp_copy(ctx->fp2_p[2][0], t1[0]);
		fp_copy(ctx->fp2_p[2][1], t1[1]);
		fp2_sqr(t1, t0);
		fp2_sqr(t1, t1);
		fp_copy(ctx->fp2_p[3][0], t1[0]);
		fp_copy(ctx->fp2_p[3][1], t1[1]);
		fp2_mul(t1, t1, t0);
		fp_copy(ctx->fp2_p[4][0], t1[0]);
		fp_copy(ctx->fp2_p[4][1], t1[1]);
#endif
		fp2_frb(t1, t0, 1);
		fp2_mul(t0, t1, t0);
		fp_copy(ctx->fp2_p2[0], t0[0]);
		fp_sqr(ctx->fp2_p2[1], ctx->fp2_p2[0]);
		fp_mul(ctx->fp2_p2[2], ctx->fp2_p2[1], ctx->fp2_p2[0]);
		fp_sqr(ctx->fp2_p2[3], ctx->fp2_p2[1]);

		for (int i = 0; i < 5; i++) {
			fp_mul(ctx->fp2_p3[i][0], ctx->fp2_p2[i % 3], ctx->fp2_p[i][0]);
			fp_mul(ctx->fp2_p3[i][1], ctx->fp2_p2[i % 3], ctx->fp2_p[i][1]);
		}

		fp2_set_dig(t1, 1);
		fp2_mul_nor(t0, t1);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 4);
		fp2_exp(t0, t0, e);
		if (fp_is_zero(t0[0])) {
			fp_copy(ctx->fp2_p2[4], t0[1]);
		} else {
			fp_copy(ctx->fp2_p2[4], t0[0]);
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(e);
		fp2_free(t0);
		fp2_free(t1);
	}
}

void fp3_field_init(void) {
	bn_t e;
	fp3_t t0, t1, t2;
	ctx_t *ctx = core_get();

	bn_null(e);
	fp3_null(t0);
	fp3_null(t1);
	fp3_null(t2);

	TRY {
		bn_new(e);
		fp3_new(t0);
		fp3_new(t1);
		fp3_new(t2);

		fp_set_dig(ctx->fp3_base[0], -fp_prime_get_cnr());
		fp_neg(ctx->fp3_base[0], ctx->fp3_base[0]);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 3);
		fp_exp(ctx->fp3_base[0], ctx->fp3_base[0], e);
		fp_sqr(ctx->fp3_base[1], ctx->fp3_base[0]);

		fp3_zero(t0);
		fp_set_dig(t0[1], 1);
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 6);

		/* t0 = u^((p-1)/6). */
		fp3_exp(t0, t0, e);
		fp_copy(ctx->fp3_p[0], t0[2]);
		fp3_sqr(t1, t0);
		fp_copy(ctx->fp3_p[1], t1[1]);
		fp3_mul(t2, t1, t0);
		fp_copy(ctx->fp3_p[2], t2[0]);
		fp3_sqr(t2, t1);
		fp_copy(ctx->fp3_p[3], t2[2]);
		fp3_mul(t2, t2, t0);
		fp_copy(ctx->fp3_p[4], t2[1]);

		fp_mul(ctx->fp3_p2[0], ctx->fp3_p[0], ctx->fp3_base[1]);
		fp_mul(t0[0], ctx->fp3_p2[0], ctx->fp3_p[0]);
		fp_neg(ctx->fp3_p2[0], t0[0]);
		for (int i = -1; i > fp_prime_get_cnr(); i--) {
			fp_sub(ctx->fp3_p2[0], ctx->fp3_p2[0], t0[0]);
		}
		fp_mul(ctx->fp3_p2[1], ctx->fp3_p[1], ctx->fp3_base[0]);
		fp_mul(ctx->fp3_p2[1], ctx->fp3_p2[1], ctx->fp3_p[1]);
		fp_sqr(ctx->fp3_p2[2], ctx->fp3_p[2]);
		fp_mul(ctx->fp3_p2[3], ctx->fp3_p[3], ctx->fp3_base[1]);
		fp_mul(t0[0], ctx->fp3_p2[3], ctx->fp3_p[3]);
		fp_neg(ctx->fp3_p2[3], t0[0]);
		for (int i = -1; i > fp_prime_get_cnr(); i--) {
			fp_sub(ctx->fp3_p2[3], ctx->fp3_p2[3], t0[0]);
		}
		fp_mul(ctx->fp3_p2[4], ctx->fp3_p[4], ctx->fp3_base[0]);
		fp_mul(ctx->fp3_p2[4], ctx->fp3_p2[4], ctx->fp3_p[4]);

		fp_mul(ctx->fp3_p3[0], ctx->fp3_p[0], ctx->fp3_base[0]);
		fp_mul(t0[0], ctx->fp3_p3[0], ctx->fp3_p2[0]);
		fp_neg(ctx->fp3_p3[0], t0[0]);
		for (int i = -1; i > fp_prime_get_cnr(); i--) {
			fp_sub(ctx->fp3_p3[0], ctx->fp3_p3[0], t0[0]);
		}
		fp_mul(ctx->fp3_p3[1], ctx->fp3_p[1], ctx->fp3_base[1]);
		fp_mul(t0[0], ctx->fp3_p3[1], ctx->fp3_p2[1]);
		fp_neg(ctx->fp3_p3[1], t0[0]);
		for (int i = -1; i > fp_prime_get_cnr(); i--) {
			fp_sub(ctx->fp3_p3[1], ctx->fp3_p3[1], t0[0]);
		}
		fp_mul(ctx->fp3_p3[2], ctx->fp3_p[2], ctx->fp3_p2[2]);
		fp_mul(ctx->fp3_p3[3], ctx->fp3_p[3], ctx->fp3_base[0]);
		fp_mul(t0[0], ctx->fp3_p3[3], ctx->fp3_p2[3]);
		fp_neg(ctx->fp3_p3[3], t0[0]);
		for (int i = -1; i > fp_prime_get_cnr(); i--) {
			fp_sub(ctx->fp3_p3[3], ctx->fp3_p3[3], t0[0]);
		}
		fp_mul(ctx->fp3_p3[4], ctx->fp3_p[4], ctx->fp3_base[1]);
		fp_mul(t0[0], ctx->fp3_p3[4], ctx->fp3_p2[4]);
		fp_neg(ctx->fp3_p3[4], t0[0]);
		for (int i = -1; i > fp_prime_get_cnr(); i--) {
			fp_sub(ctx->fp3_p3[4], ctx->fp3_p3[4], t0[0]);
		}
		for (int i = 0; i < 5; i++) {
			fp_mul(ctx->fp3_p4[i], ctx->fp3_p[i], ctx->fp3_p3[i]);
			fp_mul(ctx->fp3_p5[i], ctx->fp3_p2[i], ctx->fp3_p3[i]);
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(e);
		fp3_free(t0);
		fp3_free(t1);
		fp3_free(t2);
	}
}
