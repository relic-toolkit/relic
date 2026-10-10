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
 * Implementation of configuration of prime elliptic curves over a nonic
 * extension field.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if FP_PRIME == 569
/**
 * Generator of the order-r subgroup of the sextic twist over Fp^9.
 */
/** @{ */
#define SG54_P569_X00	"1E389F332DF2021EA1184765A5F47349F170E9230ED98CF5F35AC4DD7491E0244A2CEA197FBF7527505DD4A8455DD23C042567F3E33393A01DB07985DC2DD27826D19522060E01"
#define SG54_P569_X01	"BAE3E7B243BE1100DAED0C041346351C0937F37E71E57A18B90311457F5AEEC704B9E6697FB246AEE22CF7A5BA48F6821ACDAE053CDF35A9A32FDF789673C8F15F837035F0FE52"
#define SG54_P569_X02	"194C03CC03E3D13996CD05B07F4026FC89017EC2B8B257FE567E164A418FD42958BF835F3395D2085F7B8FE92F0048F8FB5629F9D70EF56AB2FC7495999A8EA4FEE35F34A73075"
#define SG54_P569_X10	"B068EC27D441FC14583F57494CBF3AD7117A72CF8AFBFC3B5D046E0BD0849352CF23A0E5505F25A3B17936B789803AFA7AAE3D14BDFA9CB3C9804D7516CF7295E2656F921A08B4"
#define SG54_P569_X11	"0F3350C3168AB6A4A8F0D35D6F10CB4CB56440CEC4D3E826BB5492CD370712F0D13F73B197A3F7E9BECF46F8B0FB02B354ED86A4506A1AEBBF063A1FFC3BB519AAEBDFC96637EB"
#define SG54_P569_X12	"56881E19298D0DB323F4054BEF75803E917EA9332D2A5278713FCF68AF5BFBFCF0A07AAFFB3FAEFAB271BCA40A34C489DF9E23D3235FD3C15045AD797C1C10C9261EC6006ACE11"
#define SG54_P569_X20	"E75291962F8B6069888AE07BA7B8FBFF0F6C5D82CF1B240C983F3D2FC220B90D0C52E9194B55395FBE55BF66BF6178494F0B9CC16B9ED3A0924A4A225083086D850531FF47768C"
#define SG54_P569_X21	"4F0BE29A5B0B20CC998F84BE209F1007A56A5742BEDBC9EA5768131E15EC5316B97A5A41C7F118224933BF1C170A79739153EE1DEC5A084E13DF783E14EBF34096605E181EF35A"
#define SG54_P569_X22	"3B8F6AAF5067AF990974F8BEC58E3B8151DC61646C6E523CCFDD3A27B1588993607EF700D3F8A27DDA71E3CED9324282E9F6E394433921F655BECAB2E5AC08DBA9207A8DB99D39"
#define SG54_P569_Y00	"FB32F805837AC53F50C4E9238B2808AA35A854DBF610BEF72A180B54E4BCDBFEC5706A41CF43258C6AC1DD857F3B94AE58C2F80CAB0E977B33145E481A1E8F848D15448006FF55"
#define SG54_P569_Y01	"2864D2E200BCC3383F58BFFB73A81C177343F4661A1B8CE3723EDC1AB71C89AE240B587A654E7D555DD7BFB211A43C4C463312A8A82FEBCE6B1797FE047A84265C7FD70FC00D81"
#define SG54_P569_Y02	"B1A5A2A4CD6CD5238E684B24DA6579ADC41A9EBE499524154B7F14DF2F05F08D0A296930488786F0F47523961D9AF607A924530A88F8842D420181FA8DF94EDDB5092A6B678119"
#define SG54_P569_Y10	"51BE5155AC3DB6B20222CAA2F6F115798F6D56E7C294C64B8D182FEF03FCFAB57E791C464B38CFFA81905211FADE928914B888C6CB000040EAF53CF700ED4A405E3146D63335E4"
#define SG54_P569_Y11	"08ABC2FAC0D87900C653C1279AAAD421D36571F0F1F49C126F4AA3610C72704E6E986C088350044CF9D715649015559147B3B6B80A5C45519B84AF4C302953302FE4445731F4C4"
#define SG54_P569_Y12	"C1A69378BF81042E108345F93026D0452BD9EF72262A6CFD8BF28ECEF6C80242192CFFEF77737AA474D62E5FFF1B4BFE8F8378256A2854D0B7C8B199621C22D22F827729A50F52"
#define SG54_P569_Y20	"53CBD42DF27B32598712C729913FC1E5ACDFE16063CCC1A8EDE887223B2891407917B37D811E1A93AB716693E9D04A6AD35819E5F383CC5A22B1848BADD0FEB18CBD44055858D4"
#define SG54_P569_Y21	"16DC6C7F1A5FB6FDCFBAA0944CC98398245EABA7CA607DDA5EEC6A2FBDF6DA1D6EB29A0E6941704AAF932810FEF372FE0FF7AA55C1F7EDE06B317DDED4B53D7D7F6D9A09A099D9"
#define SG54_P569_Y22	"86C9BA4E7DDA70BB3FC1CE8245638F06CABC723A31CEC1427E6627AB6BBC716C54C5B30DB951BF2C1D7E07E74CD9E15837E79BC354DA011517BEE5395BA38F32E0C2C75F089FDC"
/** @} */
#endif

/**
 * Assigns the generator of an elliptic curve over a nonic extension.
 *
 * @param[in] CURVE		- the curve parameters to assign.
 */
#define ASSIGN(CURVE)														\
	RLC_GET(str, CURVE##_X00, sizeof(CURVE##_X00));							\
	fp_read_str(g->x[0][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X01, sizeof(CURVE##_X01));							\
	fp_read_str(g->x[0][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X02, sizeof(CURVE##_X02));							\
	fp_read_str(g->x[0][2], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X10, sizeof(CURVE##_X10));							\
	fp_read_str(g->x[1][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X11, sizeof(CURVE##_X11));							\
	fp_read_str(g->x[1][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X12, sizeof(CURVE##_X12));							\
	fp_read_str(g->x[1][2], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X20, sizeof(CURVE##_X20));							\
	fp_read_str(g->x[2][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X21, sizeof(CURVE##_X21));							\
	fp_read_str(g->x[2][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X22, sizeof(CURVE##_X22));							\
	fp_read_str(g->x[2][2], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y00, sizeof(CURVE##_Y00));							\
	fp_read_str(g->y[0][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y01, sizeof(CURVE##_Y01));							\
	fp_read_str(g->y[0][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y02, sizeof(CURVE##_Y02));							\
	fp_read_str(g->y[0][2], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y10, sizeof(CURVE##_Y10));							\
	fp_read_str(g->y[1][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y11, sizeof(CURVE##_Y11));							\
	fp_read_str(g->y[1][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y12, sizeof(CURVE##_Y12));							\
	fp_read_str(g->y[1][2], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y20, sizeof(CURVE##_Y20));							\
	fp_read_str(g->y[2][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y21, sizeof(CURVE##_Y21));							\
	fp_read_str(g->y[2][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_Y22, sizeof(CURVE##_Y22));							\
	fp_read_str(g->y[2][2], str, strlen(str), 16);

/**
 * Detects an optimization based on the curve coefficients.
 */
static void detect_opt(int *opt, fp9_t a) {
	fp9_t t;
	fp9_null(t);

	RLC_TRY {
		fp9_new(t);
		fp9_set_dig(t, 3);
		fp9_neg(t, t);

		if (fp9_cmp(a, t) == RLC_EQ) {
			*opt = RLC_MIN3;
		} else if (fp9_is_zero(a)) {
			*opt = RLC_ZERO;
		} else if (fp9_cmp_dig(a, 1) == RLC_EQ) {
			*opt = RLC_ONE;
		} else if (fp9_cmp_dig(a, 2) == RLC_EQ) {
			*opt = RLC_TWO;
		} else {
			*opt = RLC_HUGE;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp9_free(t);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep9_curve_init(void) {
	ctx_t *ctx = core_get();

#ifdef EP_PRECO
	for (int i = 0; i < RLC_EP_TABLE; i++) {
		ctx->ep9_ptr[i] = &(ctx->ep9_pre[i]);
	}
#endif

#if ALLOC == DYNAMIC
	ep9_new(ctx->ep9_g);
	fp9_new(ctx->ep9_a);
	fp9_new(ctx->ep9_b);
	for (int i = 0; i < 4; i++) {
		fp9_new(ctx->ep9_frb[i]);
	}
#endif

#ifdef EP_PRECO
#if ALLOC == DYNAMIC
	for (int i = 0; i < RLC_EP_TABLE; i++) {
		fp9_new(ctx->ep9_pre[i].x);
		fp9_new(ctx->ep9_pre[i].y);
		fp9_new(ctx->ep9_pre[i].z);
	}
#endif
#endif
	bn_make(&(ctx->ep9_r), RLC_FP_DIGS);
}

void ep9_curve_clean(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
#ifdef EP_PRECO
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			fp9_free(ctx->ep9_pre[i].x);
			fp9_free(ctx->ep9_pre[i].y);
			fp9_free(ctx->ep9_pre[i].z);
		}
#endif
		bn_clean(&(ctx->ep9_r));
		ep9_free(ctx->ep9_g);
		fp9_free(ctx->ep9_a);
		fp9_free(ctx->ep9_b);
		for (int i = 0; i < 4; i++) {
			fp9_free(ctx->ep9_frb[i]);
		}
	}
}

int ep9_curve_opt_a(void) {
	return core_get()->ep9_opt_a;
}

int ep9_curve_opt_b(void) {
	return core_get()->ep9_opt_b;
}

void ep9_curve_mul_a(fp9_t c, const fp9_t a) {
	ctx_t *ctx = core_get();
	switch (ctx->ep9_opt_a) {
		case RLC_ZERO:
			fp9_zero(c);
			break;
		case RLC_ONE:
			fp9_copy(c, a);
			break;
		case RLC_TWO:
			fp9_dbl(c, a);
			break;
		default:
			fp9_mul(c, a, ctx->ep9_a);
			break;
	}
}

void ep9_curve_mul_b(fp9_t c, const fp9_t a) {
	ctx_t *ctx = core_get();
	switch (ctx->ep9_opt_b) {
		case RLC_ZERO:
			fp9_zero(c);
			break;
		case RLC_ONE:
			fp9_copy(c, a);
			break;
		default:
			if (ep9_curve_is_twist() == RLC_EP_MTYPE) {
				/* Multiply by b' = b * j as b times the adjoined root. */
				for (int i = 0; i < 3; i++) {
					for (int j = 0; j < 3; j++) {
						fp_mul(c[i][j], a[i][j], ep_curve_get_b());
					}
				}
				fp9_mul_art(c, c);
			} else {
				fp9_mul(c, a, ctx->ep9_b);
			}
			break;
	}
}

int ep9_curve_is_twist(void) {
	return core_get()->ep9_is_twist;
}

void ep9_curve_get_gen(ep9_t g) {
	ep9_copy(g, core_get()->ep9_g);
}

fp3_t *ep9_curve_get_a(void) {
	return core_get()->ep9_a;
}

fp3_t *ep9_curve_get_b(void) {
	return core_get()->ep9_b;
}

void ep9_curve_get_ord(bn_t n) {
	ctx_t *ctx = core_get();
	if (ctx->ep9_is_twist) {
		ep_curve_get_ord(n);
	} else {
		bn_copy(n, &(ctx->ep9_r));
	}
}

#if defined(EP_PRECO)

ep9_t *ep9_curve_get_tab(void) {
#if ALLOC == AUTO
	return (ep9_t *)*(core_get()->ep9_ptr);
#else
	return core_get()->ep9_ptr;
#endif
}

#endif

void ep9_curve_set_twist(int type) {
	char str[2 * RLC_FP_BYTES + 1];
	ctx_t *ctx = core_get();
	ep9_t g;
	fp9_t t;
	bn_t e;

	ep9_null(g);
	fp9_null(t);
	bn_null(e);

	ctx->ep9_is_twist = 0;
	if (type == RLC_EP_MTYPE || type == RLC_EP_DTYPE) {
		ctx->ep9_is_twist = type;
	} else {
		return;
	}

	RLC_TRY {
		ep9_new(g);
		fp9_new(t);
		bn_new(e);

		switch (ep_param_get()) {
#if FP_PRIME == 569
			case SG54_P569:
				ASSIGN(SG54_P569);
				break;
#endif
			default:
				(void)str;
				RLC_THROW(ERR_NO_VALID);
				break;
		}

		fp9_set_dig(g->z, 1);
		g->coord = BASIC;
		ep9_copy(ctx->ep9_g, g);

		/* Sextic twists only exist for a = 0, so b' = b * j^(+-1). */
		fp9_zero(t);
		fp_set_dig(t[1][0], 1);
		if (type == RLC_EP_DTYPE) {
			fp9_inv(t, t);
		}
		fp9_zero(ctx->ep9_a);
		fp9_zero(ctx->ep9_b);
		fp_copy(ctx->ep9_b[0][0], ep_curve_get_b());
		fp9_mul(ctx->ep9_b, ctx->ep9_b, t);

		detect_opt(&(ctx->ep9_opt_a), ctx->ep9_a);
		detect_opt(&(ctx->ep9_opt_b), ctx->ep9_b);

		ep_curve_get_ord(&(ctx->ep9_r));

		/* Frobenius constants are j^-((p - 1)/3) and j^-((p - 1)/2) for the
		 * multiplicative twist, and their inverses for the divisive one. */
		fp9_inv(t, t);
		e->used = RLC_FP_DIGS;
		dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
		bn_trim(e);
		bn_sub_dig(e, e, 1);
		bn_div_dig(e, e, 3);
		fp9_exp(ctx->ep9_frb[0], t, e);
		bn_mul_dig(e, e, 3);
		bn_hlv(e, e);
		fp9_exp(ctx->ep9_frb[1], t, e);

		/* Accumulate the constants for the 11th power of the Frobenius. */
		for (int i = 0; i < 2; i++) {
			fp9_copy(ctx->ep9_frb[i + 2], ctx->ep9_frb[i]);
			for (int j = 1; j < 11; j++) {
				fp9_frb(ctx->ep9_frb[i + 2], ctx->ep9_frb[i + 2], 1);
				fp9_mul(ctx->ep9_frb[i + 2], ctx->ep9_frb[i + 2],
						ctx->ep9_frb[i]);
			}
		}

#if defined(WITH_PC)
		/* Compute pairing generator. */
		pc_core_calc();
#endif

#if defined(EP_PRECO)
		ep9_mul_pre((ep9_t *)ep9_curve_get_tab(), ctx->ep9_g);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep9_free(g);
		fp9_free(t);
		bn_free(e);
	}
}

void ep9_curve_set(const fp9_t a, const fp9_t b, const ep9_t g,
		const bn_t r) {
	ctx_t *ctx = core_get();
	ctx->ep9_is_twist = 0;

	fp9_copy(ctx->ep9_a, a);
	fp9_copy(ctx->ep9_b, b);

	detect_opt(&(ctx->ep9_opt_a), ctx->ep9_a);
	detect_opt(&(ctx->ep9_opt_b), ctx->ep9_b);

	ep9_norm(ctx->ep9_g, g);
	bn_copy(&(ctx->ep9_r), r);

#if defined(EP_PRECO)
	ep9_mul_pre((ep9_t *)ep9_curve_get_tab(), ctx->ep9_g);
#endif
}
