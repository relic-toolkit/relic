/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of configuration of prime elliptic curves over octic
 * extensions.
 *
 * @ingroup epx
 */

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/* See ep/relic_ep_param.c for discussion of MAP_U parameters. */

#if defined(EP_ENDOM) && FP_PRIME == 575
/** @{ */
#define B48_P575_B0		"0"
#define B48_P575_B1		"0"
#define B48_P575_B2		"0"
#define B48_P575_B3		"0"
#define B48_P575_B4		"4"
#define B48_P575_B5		"0"
#define B48_P575_B6		"0"
#define B48_P575_B7		"0"
#define B48_P575_X0		"266A6ACAA4B8DDCFBF97F09DFBEB01999BFBFF872276FA7700114F761E8971C6C25A53CC77E96BCC9579F63D8A39D641B8070B07EF40E93C301A5B49CE87110CC30E044BEE5A2D43"
#define B48_P575_X1		"5009EEB2A67C52B79D0727B408A193FFCE76B4F80C8DCF4D61ECEE5471601CD7A94341F697CE9D375DB5470EA055B73C256CCC0AC12F52EAD276C26E001DDCE02DE634BEFCB9CC7C"
#define B48_P575_X2		"11A8DDB59724C01696BE52862B5AC2C7E1C0C42EFCAF456A80F6C6D9F95F89649D5575DE3BA8D28D1012E14308DE1D8F15CE1617611F961032B0B5DFA27EF3E3670B9B537ACC66B9"
#define B48_P575_X3		"4E8BDED03587581A173AD008DFF600EB24054E4CDDCA8D7BFABA2898822DB5ED701BF59BD3F108AD7C714B6A6C7ECB11A1BC5DEEC1D49AE7FCA597C43943A66441B03164975D9BE0"
#define B48_P575_X4		"29E2751CAC7D0FBA8E12CC818BDE6F2A7173D3C2ED74EC1991B936071DEB1AED1E07CDF71EA3501BEB4645C86BDC8A575898303FF6A058C7062F079F594E5B865626D0C031CF7E44"
#define B48_P575_X5 	"2F3A1BE54DFFB814DA4AE6311B9B1EEE6198CDB9F36CE92084272416462F4D0AC9ACAC025FDA6D3D0D1C239FE8CE4B7F22A1D0F65582DDA36EEB328843FDE5C0BDA02E871796CC8E"
#define B48_P575_X6 	"2FEE7B15EB22B05476A462374860140DCC9F00910E0555918D6357F6E32E623B88B893647AD07B615F364093D6F6D2A7B7614590A8833385B5A833563C0DD6C89AF89D06428E8AFE"
#define B48_P575_X7 	"005082322BB5E610DC0E61E3D01B8BFF23D195117F58B1FA68EC04A6769FEB754A58742C7F729E2A684386C40EFB871CB3D32A040966155649DC45C49E6FB5DEE58DB1586CBFD33E"
#define B48_P575_Y0		"3B603A4C408A402FB885B607C4A661BF92354D22F46945F222C6F51CCDEBF4006640346AE6BFD60F7E22240D4BF83EFDA1B575267A89597D7BC54FA4899BFBAAC4138E30C8DA55C0"
#define B48_P575_Y1		"35D3ECCC1F3C69A921E57CCDEA6C794A5ED01A53E19208854EA3B10D519CCCE64A30007CD7A57673567F2FFA070E5CE01C4E5C8BF1C61225DAC36A93C6524F4D0350C6358C67F85B"
#define B48_P575_Y2		"4228DA69A29E14E2CF00EC8FDD877CA9049DA161778A6ACE8DC275D4CE94C90AD9176280703AD9C6714A4865EF6160ED2FA7A5FC601025CF096AB6CF21B8FAA41421C7913DECF3B5"
#define B48_P575_Y3		"5273C1679E18D316C6988820E06335094FCCCD5E8FD870492EB96FCBC5B5494B2B9D0869C18309FF2D49CD80CF6E6FE1A660027A6E924831F8D5A070645A7B794BA7AE72507809AE"
#define B48_P575_Y4 	"0ABD2F582F0D4C3C89770C13F02FF17CDEA5B22CDD661B6F82905ADCDC44E59900C5D09F8CAC90760CCC57D1987DE4BA21F34455E5B7394B68A7883E3F8D918AF308F0C3E6F98F4B"
#define B48_P575_Y5 	"36FAE1DE9DD31FFE238526F618C14E5CB61EEA8E8E6D82235E43E45E306C5E60B4E5499BF4663516CE1202EF6CDE3B2E098E406B3186937483FC104A173707C6419F460A23ADF628"
#define B48_P575_Y6 	"09E1BB455FCB47E98C5263B5098E2D148EC2EDEE5634B8F94F10AF9221D09BD60D28920342C11B1987A24B7F56AC4F5E290E7EA483727ED16FFC88C0F5EAD00892FDA66BA68FACE4"
#define B48_P575_Y7 	"4F781C32F5CAFD446F299BE6BC600BF3482DF6ECAF4ABE3D410A7255B18A88DB77CC539CAC4A0D30A00690CCA8CC7661BCE042D0AC40FF8DC9171847A8E42696E4EF9DD8A5907A3D"
#define B48_P575_R		"FFBFC68EB6176EFB58025E547BF4EBACB1315C184DC37EAAF67BBCCE069D07F425050E765ABB8B40D5E6D7AE8A2A5698B771DDBD6E109D56D59C3DFF00000001"
#define B48_P575_H		"9E9223EB731FB087A7A45CA84E1C06F79C4326124DE74264AA1FCFB1FB41AFF2CBA999F970BD426881824E1A7562ED4F1E249817937F029045954EED2EB984ED650EF97D1189758800D5926B4CA05A197A0B8D1FD9697173D9B8389AAA1B76E1AF1AAC3B9999905ADD15F51DB643E2B16361CD2E54E7B18B29AB0A08ECF2818F8EAB997AC33C00D0901C913B44817E1E3F5B89E3CA71C8A59556AF31D4998B77BE410ADC0C19CAE9A82DEAC267087E382A39F4ADC7043BD46F38D00454D2A8D7EFA4109F3AE1157580E650F5614A3BB05A8DDFEB789CEEE1F91A31CFA50BB5E689A006B43B4D4364E3001144F12DA0A5F388DE9A09B24A00CE5D91E42C0BFDA4BBE3A59C60439B347B5A727EE436069DBF413F6190F212C5BE3F02F9381AB92830E65AA13C3D583D63C077777F32BFC912726FC49B5082059BFDC912C81C4259542DA560430230B4D0E905E3ADAA2AF0E0BEB18C5B6BC52A452BE1E70CCAC2A23F954EA5548B11FE3FD7C02940A6DA75340BB3459CCC74EA778E3B3B239FB5D1B815B929BAF390372BB0043C3A920B878F4AC32243ED6E2A7F79D85A5D66C9ED8D08A20E5EC0E9145561868EB5987EF043EF9A1176149B3618D96F9F179519B89027A2648576E807E1A4B1C8E9F5C0A147D2750E65DF130DF53D7AAD8D4EA7D0CEB1C03BAF8A0C7BE62F433C5747E851661399976495246EAF448690CD4B1"
/** @} */
#endif

/**
 * Assigns a set of ordinary elliptic curve parameters.
 *
 * @param[in] CURVE		- the curve parameters to assign.
 */
#define ASSIGN(CURVE)														\
	RLC_GET(str, CURVE##_B0, sizeof(CURVE##_B0));							\
	fp_read_str(b[0][0][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_B1, sizeof(CURVE##_B1));							\
	fp_read_str(b[0][0][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_B2, sizeof(CURVE##_B2));							\
	fp_read_str(b[0][1][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_B3, sizeof(CURVE##_B3));							\
	fp_read_str(b[0][1][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_B4, sizeof(CURVE##_B4));							\
	fp_read_str(b[1][0][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_B5, sizeof(CURVE##_B5));							\
	fp_read_str(b[1][0][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_B6, sizeof(CURVE##_B6));							\
	fp_read_str(b[1][1][0], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_B7, sizeof(CURVE##_B7));							\
	fp_read_str(b[1][1][1], str, strlen(str), 16);							\
	RLC_GET(str, CURVE##_X0, sizeof(CURVE##_X0));							\
	fp_read_str(g->x[0][0][0], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_X1, sizeof(CURVE##_X1));							\
	fp_read_str(g->x[0][0][1], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_X2, sizeof(CURVE##_X2));							\
	fp_read_str(g->x[0][1][0], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_X3, sizeof(CURVE##_X3));							\
	fp_read_str(g->x[0][1][1], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_X4, sizeof(CURVE##_X4));							\
	fp_read_str(g->x[1][0][0], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_X5, sizeof(CURVE##_X5));							\
	fp_read_str(g->x[1][0][1], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_X6, sizeof(CURVE##_X6));							\
	fp_read_str(g->x[1][1][0], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_X7, sizeof(CURVE##_X7));							\
	fp_read_str(g->x[1][1][1], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_Y0, sizeof(CURVE##_Y0));							\
	fp_read_str(g->y[0][0][0], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_Y1, sizeof(CURVE##_Y1));							\
	fp_read_str(g->y[0][0][1], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_Y2, sizeof(CURVE##_Y2));							\
	fp_read_str(g->y[0][1][0], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_Y3, sizeof(CURVE##_Y3));							\
	fp_read_str(g->y[0][1][1], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_Y4, sizeof(CURVE##_Y4));							\
	fp_read_str(g->y[1][0][0], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_Y5, sizeof(CURVE##_Y5));							\
	fp_read_str(g->y[1][0][1], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_Y6, sizeof(CURVE##_Y6));							\
	fp_read_str(g->y[1][1][0], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_Y7, sizeof(CURVE##_Y7));							\
	fp_read_str(g->y[1][1][1], str, strlen(str), 16);						\
	RLC_GET(str, CURVE##_R, sizeof(CURVE##_R));								\
	bn_read_str(r, str, strlen(str), 16);									\
	RLC_GET(str, CURVE##_H, sizeof(CURVE##_H));								\
	bn_read_str(h, str, strlen(str), 16);									\

/**
 * Detects an optimization based on the curve coefficients.
 */
static void detect_opt(int *opt, fp8_t a) {
	fp8_t t;
	fp8_null(t);

	RLC_TRY {
		fp8_new(t);
		fp8_set_dig(t, 3);
		fp8_neg(t, t);

		if (fp8_cmp(a, t) == RLC_EQ) {
			*opt = RLC_MIN3;
		} else if (fp8_is_zero(a)) {
			*opt = RLC_ZERO;
		} else if (fp8_cmp_dig(a, 1) == RLC_EQ) {
			*opt = RLC_ONE;
		} else if (fp8_cmp_dig(a, 2) == RLC_EQ) {
			*opt = RLC_TWO;
		} else if ((fp_bits(a[0][0][0]) <= RLC_DIG) && fp_is_zero(a[0][0][1]) &&
				fp2_is_zero(a[0][1]) && fp4_is_zero(a[1])) {
			*opt = RLC_TINY;
		} else {
			*opt = RLC_HUGE;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		fp8_free(t);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void ep8_curve_init(void) {
	ctx_t *ctx = core_get();

#ifdef EP_PRECO
	for (int i = 0; i < RLC_EP_TABLE; i++) {
		ctx->ep8_ptr[i] = &(ctx->ep8_pre[i]);
	}
#endif

#if ALLOC == DYNAMIC
	ep8_new(ctx->ep8_g);
	fp8_new(ctx->ep8_a);
	fp8_new(ctx->ep8_b);
#endif

#ifdef EP_PRECO
#if ALLOC == DYNAMIC
	for (int i = 0; i < RLC_EP_TABLE; i++) {
		fp8_new(ctx->ep8_pre[i].x);
		fp8_new(ctx->ep8_pre[i].y);
		fp8_new(ctx->ep8_pre[i].z);
	}
#endif
#endif
	ep8_set_infty(ctx->ep8_g);
	bn_make(&(ctx->ep8_r), RLC_FP_DIGS);
	bn_make(&(ctx->ep8_h), RLC_FP_DIGS);
}

void ep8_curve_clean(void) {
	ctx_t *ctx = core_get();
	if (ctx != NULL) {
#ifdef EP_PRECO
		for (int i = 0; i < RLC_EP_TABLE; i++) {
			fp8_free(ctx->ep8_pre[i].x);
			fp8_free(ctx->ep8_pre[i].y);
			fp8_free(ctx->ep8_pre[i].z);
		}
#endif
		bn_clean(&(ctx->ep8_r));
		bn_clean(&(ctx->ep8_h));
		ep8_free(ctx->ep8_g);
		fp8_free(ctx->ep8_a);
		fp8_free(ctx->ep8_b);
	}
}

int ep8_curve_opt_a(void) {
	return core_get()->ep8_opt_a;
}

int ep8_curve_opt_b(void) {
	return core_get()->ep8_opt_b;
}

int ep8_curve_is_twist(void) {
	return core_get()->ep8_is_twist;
}

void ep8_curve_get_gen(ep8_t g) {
	ep8_copy(g, core_get()->ep8_g);
}

void ep8_curve_get_a(fp8_t a) {
	fp8_copy(a, core_get()->ep8_a);
}

void ep8_curve_get_b(fp8_t b) {
	fp8_copy(b, core_get()->ep8_b);
}

void ep8_curve_get_ord(bn_t n) {
	ctx_t *ctx = core_get();
	if (ctx->ep8_is_twist) {
		ep_curve_get_ord(n);
	} else {
		bn_copy(n, &(ctx->ep8_r));
	}
}

void ep8_curve_get_cof(bn_t h) {
	bn_copy(h, &(core_get()->ep8_h));
}

#if defined(EP_PRECO)

ep8_t *ep8_curve_get_tab(void) {
#if ALLOC == AUTO
	return (ep8_t *)*(core_get()->ep8_ptr);
#else
	return core_get()->ep8_ptr;
#endif
}

#endif

void ep8_curve_set_twist(int type) {
	char str[16 * RLC_FP_BYTES + 1];
	ctx_t *ctx = core_get();
	ep8_t g;
	fp8_t a, b;
	bn_t r, h;

	ep8_null(g);
	fp8_null(a);
	fp8_null(b);
	bn_null(r);
	bn_null(h);

	ctx->ep8_is_twist = 0;
	if (type == RLC_EP_MTYPE || type == RLC_EP_DTYPE) {
		ctx->ep8_is_twist = type;
	} else {
		return;
	}

	RLC_TRY {
		ep8_new(g);
		fp8_new(a);
		fp8_new(b);
		bn_new(r);
		bn_new(h);

		switch (ep_param_get()) {
#if FP_PRIME == 575
			case B48_P575:
				fp8_zero(a);
				ASSIGN(B48_P575);
				break;
#endif
			default:
				(void)str;
				RLC_THROW(ERR_NO_VALID);
				break;
		}

		fp8_zero(g->z);
		fp8_set_dig(g->z, 1);
		g->coord = BASIC;

		ep8_copy(ctx->ep8_g, g);
		fp8_copy(ctx->ep8_a, a);
		fp8_copy(ctx->ep8_b, b);

		detect_opt(&(ctx->ep8_opt_a), ctx->ep8_a);
		detect_opt(&(ctx->ep8_opt_b), ctx->ep8_b);

		bn_copy(&(ctx->ep8_r), r);
		bn_copy(&(ctx->ep8_h), h);

		if (type == RLC_EP_MTYPE) {
			fp8_zero(a);
			fp_copy(a[1][1][0], ctx->fp8_p1[0]);
			fp_copy(a[1][1][1], ctx->fp8_p1[1]);
			fp8_inv(a, a);
			fp_copy(ctx->fp8_p1[0], a[1][0][0]);
			fp_copy(ctx->fp8_p1[1], a[1][0][1]);
		}

#if defined(WITH_PC)
		/* Compute pairing generator. */
		pc_core_calc();
#endif

#if defined(EP_PRECO)
		ep8_mul_pre((ep8_t *)ep8_curve_get_tab(), ctx->ep8_g);
#endif
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep8_free(g);
		fp8_free(a);
		fp8_free(b);
		bn_free(r);
		bn_free(h);
	}
}

void ep8_curve_set(const fp8_t a, const fp8_t b, const ep8_t g, const bn_t r, const bn_t h) {
	ctx_t *ctx = core_get();
	ctx->ep8_is_twist = 0;

	fp8_copy(ctx->ep8_a, a);
	fp8_copy(ctx->ep8_b, b);

	ep8_norm(ctx->ep8_g, g);
	bn_copy(&(ctx->ep8_r), r);
	bn_copy(&(ctx->ep8_h), h);

#if defined(EP_PRECO)
	ep8_mul_pre((ep8_t *)ep8_curve_get_tab(), ctx->ep8_g);
#endif
}
