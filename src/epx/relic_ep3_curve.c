/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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
 * Implementation of configuration of prime elliptic curves over quartic
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/* See ep/relic_ep_param.c for discussion of MAP_U parameters. */

#if defined(EP_ENDOM) && FP_PRIME == 638
/** @{ */
#define K18_P638_A0		"0"
#define K18_P638_A1		"0"
#define K18_P638_A2		"0"
#define K18_P638_B0		"30"
#define K18_P638_B1		"6"
#define K18_P638_B2		"0"
#define K18_P638_X0		"190CA4C3742BC18984EF7233FFC5C472E75224DD809610572F31856CBB7558860969792C3A8C9446776D457E4A6BBE54D31778C83807F13792AD3DA6E1BB6368EDE4EB477480489B62C584E054D605D6"
#define K18_P638_X1		"091FBBC70A6B3B535966FDE55003C9361698CA2D7B2A37A7B463020D482EB2F79A22852DD2D22A22E715B8239BBC96B934E2D8EC5DADD8787581505B95A00F53246C477C08E227762CFF28D11B6E231A"
#define K18_P638_X2		"18E6B3B691BDE40E10047884C81949EC6ECD1A57C3E7C2AE0CD61F27EA3CF124744F51E3701A991292B80FB4A244CB7D8B7F489477E33404BE2E7350D8BC1DC64EAC44342A16F62274BAE5B508168536"
#define K18_P638_Y0		"1AD91EDBA8E17771FDB1642D032D2D4DA22CE1DDE103D931103E11E90F2BA16681D0CF10DCD1E2850C0A4CD5089EEF0F97263975C010C1218282D9480E71E50185FC1AE89C45E7204CD5A9901D164EDC"
#define K18_P638_Y1		"1816541B49022D5CC2083B435671DC75D1B4AF689CB16D40DC5EF107AE59890482B5403326B81F2F2F0041AE4E50594183153E5594C91FC6DC9F009495717FC39312C05BF28969922A0DBC0FAF7BD462"
#define K18_P638_Y2		"1B5D53508B5C4B3044EA882874D0743C38CA445ED36A84F353AF4EA0291E81E3618B8E515C63E122D181F376035A13403DD1F5D14BCB2726434EA2512A842F334D9928D2BA65F3FEA3A858FC231F1E66"
#define K18_P638_R		"217C6AD09A8C1501A39F40A5CAE9A8FA6C1D721892617A6D5AB381B7B89EF9B4A91AE277CAAA0EE0BC3E2910806BDC08EA69545693C740000000001"
#define K18_P638_H		"D10F161A65711BAE126EE4D96E29E6BF525A11BD7BC76B44C5EFF1E59229DCDCAC7CDF4627E564E2046C46D868DA9C8A13B6DF56D99B94D915E385CDC71C047AA9B5E11835A3B37571D1822F23B77B2ECA4F71FC1DF25E659264279F89AB8F7490ED9354E08614239C571B3BD7DDAD3C6C8DD23E27CC0F87C40EE0945B05D3349FE931900ACE29582AF47FCD57C6C3ADCF1F67FFEE4767D4ECB7969FEC7AFFC48C84E9719C0A2C2D4D830FCDEA56F4F1F3CECB6B"
/** @} */
#endif

/**
 * Assigns a set of ordinary elliptic curve parameters.
 *
 * @param[in] CURVE		- the curve parameters to assign.
 */
#define ASSIGN(CURVE)														\
	RLC_GET(str, CURVE##_A0, sizeof(CURVE##_A0));							\
	fp_read_str(a[0], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_A1, sizeof(CURVE##_A1));							\
	fp_read_str(a[1], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_A2, sizeof(CURVE##_A2));							\
	fp_read_str(a[2], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B0, sizeof(CURVE##_B0));							\
	fp_read_str(b[0], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B1, sizeof(CURVE##_B1));							\
	fp_read_str(b[1], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_B2, sizeof(CURVE##_B2));							\
	fp_read_str(b[2], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_X0, sizeof(CURVE##_X0));							\
	fp_read_str(g->x[0], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_X1, sizeof(CURVE##_X1));							\
	fp_read_str(g->x[1], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_X2, sizeof(CURVE##_X2));							\
	fp_read_str(g->x[2], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_Y0, sizeof(CURVE##_Y0));							\
	fp_read_str(g->y[0], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_Y1, sizeof(CURVE##_Y1));							\
	fp_read_str(g->y[1], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_Y2, sizeof(CURVE##_Y2));							\
	fp_read_str(g->y[2], str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_R, sizeof(CURVE##_R));								\
	bn_read_str(r, str, strlen(str), 16);									\
	RLC_GET(str, CURVE##_H, sizeof(CURVE##_H));								\
	bn_read_str(h, str, strlen(str), 16);									\

/**
 * Detects an optimization based on the curve coefficients.
 */
static void detect_opt(int *opt, fp3_t a) {
	fp3_t t;
	fp3_null(t);

	RLC_TRY {
		fp3_new(t);
		fp3_set_dig(t, 3);
		fp3_neg(t, t);

		if (fp3_cmp(a, t) == RLC_EQ) {
			*opt = RLC_MIN3;
		} else if (fp3_is_zero(a)) {
			*opt = RLC_ZERO;
		} else if (fp3_cmp_dig(a, 1) == RLC_EQ) {
			*opt = RLC_ONE;
		} else if (fp3_cmp_dig(a, 2) == RLC_EQ) {
			*opt = RLC_TWO;
		} else if ((fp_bits(a[0]) <= RLC_DIG) && fp_is_zero(a[1]) &&
				fp_is_zero(a[2])) {
			*opt = RLC_TINY;
		} else {
			*opt = RLC_HUGE;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp3_free(t);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep3_curve_init(void) {
	ctx_t *ctx = core_get();

#ifdef EP_PRECO
	for (int i = 0; i < RLC_EP_TABLE; i++) {
		ctx->ep3_ptr[i] = &(ctx->ep3_pre[i]);
	}
#endif

#if ALLOC == DYNAMIC
	ep3_new(ctx->ep3_g);
	fp3_new(ctx->ep3_a);
	fp3_new(ctx->ep3_b);
#endif

#ifdef EP_PRECO
#if ALLOC == DYNAMIC
	for (int i = 0; i < RLC_EP_TABLE; i++) {
		fp3_new(ctx->ep3_pre[i].x);
		fp3_new(ctx->ep3_pre[i].y);
		fp3_new(ctx->ep3_pre[i].z);
	}
#endif
#endif
	ep3_set_infty(ctx->ep3_g);
	bn_make(&(ctx->ep3_r), RLC_FP_DIGS);
	bn_make(&(ctx->ep3_h), RLC_FP_DIGS);
}

void ep3_curve_clean(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
#ifdef EP_PRECO
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			fp3_free(ctx->ep3_pre[i].x);
			fp3_free(ctx->ep3_pre[i].y);
			fp3_free(ctx->ep3_pre[i].z);
		}
#endif
		bn_clean(&(ctx->ep3_r));
		bn_clean(&(ctx->ep3_h));
		ep3_free(ctx->ep3_g);
		fp3_free(ctx->ep3_a);
		fp3_free(ctx->ep3_b);
	}
}

int ep3_curve_opt_a(void) {
	return core_get()->ep3_opt_a;
}

int ep3_curve_opt_b(void) {
	return core_get()->ep3_opt_b;
}

int ep3_curve_is_twist(void) {
	return core_get()->ep3_is_twist;
}

void ep3_curve_get_gen(ep3_t g) {
	ep3_copy(g, core_get()->ep3_g);
}

void ep3_curve_get_a(fp3_t a) {
	fp3_copy(a, core_get()->ep3_a);
}

void ep3_curve_get_b(fp3_t b) {
	fp3_copy(b, core_get()->ep3_b);
}

void ep3_curve_get_vs(bn_t *v) {
	bn_t x, t;

	bn_null(x);
	bn_null(t);

	RLC_TRY {
		bn_new(x);
		bn_new(t);

		fp_prime_get_par(x);
		bn_copy(v[1], x);
		bn_copy(v[2], x);
		bn_copy(v[3], x);

		/* t = 2x^2. */
		bn_sqr(t, x);
		bn_dbl(t, t);

		/* v0 = 2x^2 + 3x + 1. */
		bn_mul_dig(v[0], x, 3);
		bn_add_dig(v[0], v[0], 1);
		bn_add(v[0], v[0], t);

		/* v3 = -(2x^2 + x). */
		bn_add(v[3], v[3], t);
		bn_neg(v[3], v[3]);

		/* v1 = 12x^3 + 8x^2 + x, v2 = 6x^3 + 4x^2 + x. */
		bn_dbl(t, t);
		bn_add(v[2], v[2], t);
		bn_dbl(t, t);
		bn_add(v[1], v[1], t);
		bn_rsh(t, t, 2);
		bn_mul(t, t, x);
		bn_mul_dig(t, t, 3);
		bn_add(v[2], v[2], t);
		bn_dbl(t, t);
		bn_add(v[1], v[1], t);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(x);
		bn_free(t);
	}
}

void ep3_curve_get_ord(bn_t n) {
	ctx_t *ctx = core_get();
	if (ctx->ep3_is_twist) {
		ep_curve_get_ord(n);
	} else {
		bn_copy(n, &(ctx->ep3_r));
	}
}

void ep3_curve_get_cof(bn_t h) {
	bn_copy(h, &(core_get()->ep3_h));
}

#if defined(EP_PRECO)

ep3_t *ep3_curve_get_tab(void) {
#if ALLOC == AUTO
	return (ep3_t *)*(core_get()->ep3_ptr);
#else
	return core_get()->ep3_ptr;
#endif
}

#endif

void ep3_curve_set_twist(int type) {
	char str[8 * RLC_FP_BYTES + 1];
	ctx_t *ctx = core_get();
	ep3_t g;
	fp3_t a, b;
	fp18_t c;
	bn_t r, h;

	ep3_null(g);
	fp3_null(a);
	fp3_null(b);
	fp18_null(c);
	bn_null(r);
	bn_null(h);

	ctx->ep3_is_twist = 0;
	if (type == RLC_EP_MTYPE || type == RLC_EP_DTYPE) {
		ctx->ep3_is_twist = type;
	} else {
		return;
	}

	RLC_TRY {
		ep3_new(g);
		fp3_new(a);
		fp3_new(b);
		fp18_new(c);
		bn_new(r);
		bn_new(h);

		switch (ep_param_get()) {
#if FP_PRIME == 638
			case K18_P638:
				ASSIGN(K18_P638);
				break;
#endif
			default:
				(void)str;
				RLC_THROW(ERR_NO_VALID);
				break;
		}

		fp3_zero(g->z);
		fp3_set_dig(g->z, 1);
		g->coord = BASIC;

		ep3_copy(ctx->ep3_g, g);
		fp3_copy(ctx->ep3_a, a);
		fp3_copy(ctx->ep3_b, b);

		detect_opt(&(ctx->ep3_opt_a), ctx->ep3_a);
		detect_opt(&(ctx->ep3_opt_b), ctx->ep3_b);

		bn_copy(&(ctx->ep3_r), r);
		bn_copy(&(ctx->ep3_h), h);

		fp_copy(ctx->ep3_frb[0][0], ctx->fp3_p1[1][0]);
		fp_copy(ctx->ep3_frb[0][1], ctx->fp3_p1[1][1]);
		fp_copy(ctx->ep3_frb[0][2], ctx->fp3_p1[1][2]);
		fp_copy(ctx->ep3_frb[1][0], ctx->fp3_p1[2][0]);
		fp_copy(ctx->ep3_frb[1][1], ctx->fp3_p1[2][1]);
		fp_copy(ctx->ep3_frb[1][2], ctx->fp3_p1[2][2]);
		if (type == RLC_EP_MTYPE) {
			fp3_inv(ctx->ep3_frb[0], ctx->ep3_frb[0]);
			fp3_inv(ctx->ep3_frb[1], ctx->ep3_frb[1]);
		}

		fp18_zero(c);
		fp9_set_dig(c[1], 1);
		fp18_inv(c, c);
		fp3_copy(ctx->ep3_frb[2], c[1][2]);

#if defined(WITH_PC)
		/* Compute pairing generator. */
		pc_core_calc();
#endif

#if defined(EP_PRECO)
		ep3_mul_pre((ep3_t *)ep3_curve_get_tab(), ctx->ep3_g);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep3_free(g);
		fp3_free(a);
		fp3_free(b);
		fp18_free(c);
		bn_free(r);
		bn_free(h);
	}
}

void ep3_curve_set(const fp3_t a, const fp3_t b, const ep3_t g, const bn_t r, const bn_t h) {
	ctx_t *ctx = core_get();
	ctx->ep3_is_twist = 0;

	fp3_copy(ctx->ep3_a, a);
	fp3_copy(ctx->ep3_b, b);

	ep3_norm(ctx->ep3_g, g);
	bn_copy(&(ctx->ep3_r), r);
	bn_copy(&(ctx->ep3_h), h);

#if defined(EP_PRECO)
	ep3_mul_pre((ep3_t *)ep3_curve_get_tab(), ctx->ep3_g);
#endif
}
