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
 * Implementation of the prime field prime manipulation functions.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_ep.h"
#include "relic_fpx.h"
#include "relic_bn_low.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Assigns the prime field modulus.
 *
 * @param[in] p			- the new prime field modulus.
 */
static void fp_prime_set(const bn_t p) {
	dv_t s, q;
	bn_t t;
	fp_t r;
	ctx_t *ctx = core_get();

	if (p->used != RLC_FP_DIGS) {
		THROW(ERR_NO_VALID);
	}

	dv_null(s);
	bn_null(t);
	dv_null(q);
	fp_null(r);

	TRY {
		dv_new(s);
		bn_new(t);
		dv_new(q);
		fp_new(r);

		bn_copy(&(ctx->prime), p);

		#if FP_RDC == MONTY || !defined(STRIP)
				bn_mod_pre_monty(t, &(ctx->prime));
				ctx->u = t->dp[0];
				dv_zero(s, 2 * RLC_FP_DIGS);
				s[2 * RLC_FP_DIGS] = 1;
				dv_zero(q, 2 * RLC_FP_DIGS + 1);
				dv_copy(q, ctx->prime.dp, RLC_FP_DIGS);
				bn_divn_low(t->dp, ctx->conv.dp, s, 2 * RLC_FP_DIGS + 1, q, RLC_FP_DIGS);
				ctx->conv.used = RLC_FP_DIGS;
				bn_trim(&(ctx->conv));
				bn_set_dig(&(ctx->one), 1);
				bn_lsh(&(ctx->one), &(ctx->one), ctx->prime.used * RLC_DIG);
				bn_mod(&(ctx->one), &(ctx->one), &(ctx->prime));
		#endif

		/* Now look for proper quadratic/cubic non-residues. */
		ctx->qnr = ctx->cnr = 0;
		bn_mod_dig(&(ctx->mod8), &(ctx->prime), 8);

		switch (ctx->mod8) {
			case 3:
			case 7:
				ctx->qnr = -1;
				/* The current code for extensions of Fp^3 relies on qnr being
				 * also a cubic non-residue, so avoid that. */
				ctx->cnr = 0;
				break;
			case 1:
			case 5:
				ctx->qnr = ctx->cnr = -2;
				/* Check if it is a quadratic non-residue or find another. */
				fp_set_dig(r, -ctx->qnr);
				fp_neg(r, r);
				while (fp_srt(r, r) == 1) {
					ctx->qnr--;
					fp_set_dig(r, -ctx->qnr);
					fp_neg(r, r);
					/* We cannot guarantee a cubic extension anymore. */
					ctx->cnr = 0;
				};
				break;
		}
#ifdef FP_QNRES
		if (ctx->mod8 != 3) {
			THROW(ERR_NO_VALID);
		}
#endif

		fp_prime_calc();
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(t);
		dv_free(s);
		dv_free(q);
		fp_free(r);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_prime_init(void) {
	ctx_t *ctx = core_get();
	ctx->fp_id = 0;
	bn_init(&(ctx->prime), RLC_FP_DIGS);
#if FP_RDC == QUICK || !defined(STRIP)
	ctx->sps_len = 0;
	memset(ctx->sps, 0, sizeof(ctx->sps));
#endif
#if FP_RDC == MONTY || !defined(STRIP)
	bn_init(&(ctx->conv), RLC_FP_DIGS);
	bn_init(&(ctx->one), RLC_FP_DIGS);
#endif
}

void fp_prime_clean(void) {
	ctx_t *ctx = core_get();
	ctx->fp_id = 0;
#if FP_RDC == QUICK || !defined(STRIP)
	ctx->sps_len = 0;
	memset(ctx->sps, 0, sizeof(ctx->sps));
#endif
#if FP_RDC == MONTY || !defined(STRIP)
	bn_clean(&(ctx->one));
	bn_clean(&(ctx->conv));
#endif
	bn_clean(&(ctx->prime));
}

const dig_t *fp_prime_get(void) {
	return core_get()->prime.dp;
}

const dig_t *fp_prime_get_rdc(void) {
	return &(core_get()->u);
}

void fp_prime_get_par(bn_t x) {
	bn_copy(x, &(core_get()->par));
}

const int *fp_prime_get_par_sps(int *len) {
	ctx_t *ctx = core_get();
	if (ctx->par_len > 0) {
		if (len != NULL) {
			*len = ctx->par_len;
		}
		return ctx->par_sps;
	}
	if (len != NULL) {
		*len = 0;
	}
	return NULL;
}

const int *fp_prime_get_sps(int *len) {
#if FP_RDC == QUICK || !defined(STRIP)
	ctx_t *ctx = core_get();
	if (ctx->sps_len > 0 && ctx->sps_len < RLC_TERMS) {
		if (len != NULL) {
			*len = ctx->sps_len;
		}
		return ctx->sps;
	} else {
		if (len != NULL) {
			*len = 0;
		}
		return NULL;
	}
#else
	return NULL;
#endif
}

const dig_t *fp_prime_get_conv(void) {
#if FP_RDC == MONTY || !defined(STRIP)
	return core_get()->conv.dp;
#else
	return NULL;
#endif
}

dig_t fp_prime_get_mod8(void) {
	return core_get()->mod8;
}

int fp_prime_get_qnr(void) {
	return core_get()->qnr;
}

int fp_prime_get_cnr(void) {
	return core_get()->cnr;
}

void fp_prime_set_dense(const bn_t p) {
	fp_prime_set(p);
#if FP_RDC == QUICK
	THROW(ERR_NO_CONFIG);
#endif
}

void fp_prime_set_pairf(const bn_t x, int pairf) {
	bn_t p, t0, t1;
	ctx_t *ctx = core_get();
	int len = bn_bits(x) + 1;
	int8_t *s = RLC_ALLOCA(int8_t, len);

	bn_null(p);
	bn_null(t0);
	bn_null(t1);

	TRY {
		bn_new(p);
		bn_new(t0);
		bn_new(t1);

		bn_copy(&(ctx->par), x);
		bn_copy(t0, x);
		if (pairf == EP_BN) {
			/* p = 36 * x^4 + 36 * x^3 + 24 * x^2 + 6 * x + 1. */
			bn_set_dig(p, 1);
			bn_mul_dig(t1, t0, 6);
			bn_add(p, p, t1);
			bn_mul(t1, t0, t0);
			bn_mul_dig(t1, t1, 24);
			bn_add(p, p, t1);
			bn_mul(t1, t0, t0);
			bn_mul(t1, t1, t0);
			bn_mul_dig(t1, t1, 36);
			bn_add(p, p, t1);
			bn_mul(t0, t0, t0);
			bn_mul(t1, t0, t0);
			bn_mul_dig(t1, t1, 36);
			bn_add(p, p, t1);
			fp_prime_set_dense(p);
		}

		if (pairf == EP_B12) {
			/* p = (x^2 - 2x + 1) * (x^4 - x^2 + 1)/3 + x. */
			bn_sqr(t1, t0);
			bn_sqr(p, t1);
			bn_sub(p, p, t1);
			bn_add_dig(p, p, 1);
			bn_sub(t1, t1, t0);
			bn_sub(t1, t1, t0);
			bn_add_dig(t1, t1, 1);
			bn_mul(p, p, t1);
			bn_div_dig(p, p, 3);
			bn_add(p, p, t0);
			fp_prime_set_dense(p);
		}

		if (pairf == EP_OT) {
			/* p = (x^8 + x^6 + 5*x^4 + x^2 + 4*x + 4) / 4. */
			bn_set_dig(p, 4);
			bn_mul_dig(t1, t0, 4);
			bn_add(p, p, t1);
			bn_sqr(t0, t0);
			bn_add(p, p, t0);
			bn_sqr(t1, t0);
			bn_add(p, p, t1);
			bn_add(p, p, t1);
			bn_add(p, p, t1);
			bn_add(p, p, t1);
			bn_add(p, p, t1);
			bn_mul(t1, t1, t0);
			bn_add(p, p, t1);
			bn_mul(t1, t1, t0);
			bn_add(p, p, t1);
			bn_div_dig(p, p, 4);
			fp_prime_set_dense(p);
		}

		/* Store parameter in NAF form. */
		ctx->par_len = 0;
		bn_rec_naf(s, &len, &(ctx->par), 2);
		/* Fix corner case to avoid problems with sparse representation. */
		if (s[0] == -1) {
			s[0] = 1;
			s[1] = -1;
		}
		for (int i = 0; i < len && ctx->par_len < RLC_TERMS; i++) {
			if (s[i] > 0) {
				ctx->par_sps[ctx->par_len++] = i;
			}
			if (s[i] < 0) {
				ctx->par_sps[ctx->par_len++] = -i;
			}
		}
		if (ctx->par_len == RLC_TERMS) {
			THROW(ERR_NO_VALID);
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(p);
		bn_free(t0);
		bn_free(t1);
	}
}

void fp_prime_set_pmers(const int *f, int len) {
	bn_t p, t;

	bn_null(p);
	bn_null(t);

	TRY {
		bn_new(p);
		bn_new(t);

		if (len >= RLC_TERMS) {
			THROW(ERR_NO_VALID);
		}

		bn_set_2b(p, f[len - 1]);
		for (int i = len - 2; i > 0; i--) {
			if (f[i] > 0) {
				bn_set_2b(t, f[i]);
				bn_add(p, p, t);
			} else {
				bn_set_2b(t, -f[i]);
				bn_sub(p, p, t);
			}
		}
		if (f[0] > 0) {
			bn_add_dig(p, p, f[0]);
		} else {
			bn_sub_dig(p, p, -f[0]);
		}

#if FP_RDC == QUICK || !defined(STRIP)
		ctx_t *ctx = core_get();
		for (int i = 0; i < len; i++) {
			ctx->sps[i] = f[i];
		}
		ctx->sps[len] = 0;
		ctx->sps_len = len;
#endif /* FP_RDC == QUICK */

		fp_prime_set(p);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(p);
		bn_free(t);
	}
}

void fp_prime_calc(void) {
	fp_t t;

	fp_null(t);

	TRY {
		fp_new(t);

		#ifdef WITH_ED
			fp_set_dig(t, 1);
			fp_neg(t, t);
			fp_srt(core_get()->srm1, t);
		#endif

		#ifdef WITH_EP
			fp_set_dig(t, 3);
			fp_neg(t, t);
			fp_srt(core_get()->srm3, t);
		#endif

		#ifdef WITH_FPX
			if (fp_prime_get_qnr() != 0) {
				fp2_field_init();
			}
			if (fp_prime_get_cnr() != 0) {
				fp3_field_init();
			}
		#endif
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		fp_free(t);
	}
}

void fp_prime_conv(fp_t c, const bn_t a) {
	bn_t t;

	bn_null(t);

	TRY {
		bn_new(t);

#if FP_RDC == MONTY
		bn_mod(t, a, &(core_get()->prime));
		bn_lsh(t, t, RLC_FP_DIGS * RLC_DIG);
		bn_mod(t, t, &(core_get()->prime));
		dv_copy(c, t->dp, RLC_FP_DIGS);
#else
		if (a->used > RLC_FP_DIGS) {
			THROW(ERR_NO_PRECI);
		}

		bn_mod(t, a, &(core_get()->prime));

		if (bn_is_zero(t)) {
			fp_zero(c);
		} else {
			int i;
			for (i = 0; i < t->used; i++) {
				c[i] = t->dp[i];
			}
			for (; i < RLC_FP_DIGS; i++) {
				c[i] = 0;
			}
		}
		(void)t;
#endif
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(t);
	}
}

void fp_prime_conv_dig(fp_t c, dig_t a) {
	dv_t t;
	ctx_t *ctx = core_get();

	bn_null(t);

	TRY {
		dv_new(t);

#if FP_RDC == MONTY
		if (a != 1) {
			dv_zero(t, 2 * RLC_FP_DIGS + 1);
			t[RLC_FP_DIGS] = fp_mul1_low(t, ctx->conv.dp, a);
			fp_rdc(c, t);
		} else {
			dv_copy(c, ctx->one.dp, RLC_FP_DIGS);
		}
#else
		(void)ctx;
		fp_zero(c);
		c[0] = a;
#endif
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		dv_free(t);
	}
}

void fp_prime_back(bn_t c, const fp_t a) {
	dv_t t;
	int i;

	dv_null(t);

	TRY {
		dv_new(t);

		bn_grow(c, RLC_FP_DIGS);
		for (i = 0; i < RLC_FP_DIGS; i++) {
			c->dp[i] = a[i];
		}
#if FP_RDC == MONTY
		dv_zero(t, 2 * RLC_FP_DIGS + 1);
		dv_copy(t, a, RLC_FP_DIGS);
		fp_rdc(c->dp, t);
#endif
		c->used = RLC_FP_DIGS;
		c->sign = RLC_POS;
		bn_trim(c);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		dv_free(t);
	}
}
