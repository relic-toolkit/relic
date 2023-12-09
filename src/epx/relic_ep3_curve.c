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

#if defined(EP_ENDOM) && FP_PRIME == 508
/**
 * Parameters for a pairing-friendly prime curve over a quadratic extension.
 */
/** @{ */
#define K18_P508_A0		"0"
#define K18_P508_A1		"0"
#define K18_P508_A2		"0"
#define K18_P508_B0		"0"
#define K18_P508_B1		"0"
#define K18_P508_B2		"1"
#define K18_P508_X0		"0481B38AB0B95B9F699145EE9E0F5BB85063ADEC07039B7464F659BEAB3CC3AE5157FCB2D4F5D88503AAF143C9A9D039A351AA833A08506F7F079885DF87D8D"
#define K18_P508_X1		"AE31CBE29A26EF9A326FC66011A14B6DE0C28B0E117DD8EB86741147BDC64FEE7676A00F3E824BAAEF393CC9BED562D2E5B2F307278ACE7F75A9664F06331FC"
#define K18_P508_X2		"A7B35C55E843DD3D9C8D1785C3023D5983AF01D86662DCFAED2BB86798BE458539192D4E3CCA863D6A9D1E7B9DEBF7DCAB8AD3D8708BE2D79057F3191ADDD16"
#define K18_P508_Y0		"A9E391BA5067387349BAB815425F98056D9841347A1D4B18EBD2C3AA409389F972559F3605324A71BDB3D6AD2F019AA11078B9CF6DE4CF2BEEAF383AFD2936E"
#define K18_P508_Y1		"B4783EC28E495F56D7E84F616367F95BC34F4A23031E5944066F611AA47EB1538EFACDC386CDA4BE64F845ACC2097B93891ECB5DAF450BF817A5CEA3ED70021"
#define K18_P508_Y2		"016AAD68D7ABF2F5AA8910FDE09231927194F3EE1507264418367CBA2DAC99666E0FE4E7FD65D604198E858E0DF718AC2F1B35246DC4087ECE1580FCFA9FE14"
#define K18_P508_R		"BF33E1C9934E7868ECE51D291E5644DA8A2F179CEE74854EE6819B240F20CE4E7D19F4CDABA6EAEA5B0E3000000001"
#define K18_P508_H		"9806E5E0CE73547F36E994F52B22DD8416121B7A9BA69D6384DFD0B9B51D54E2090C657EF80A51D82E653A1E7902C7FB690AC973C4CA83469894F5F75495B65B1185A9AD5AF835E3F2B54A4E90CDA9F00FF09AFF09AC5BF7B13ACCE2E862BB30718D4D9806D5488EB4BDA0B0D5A5B770050C4FA6C9148DA1C77BEBE19701967DAA73F47B10D257F2A942F1860DCEB6B"
/** @} */
#endif

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

/** @{ */
#define SG18_P638_A0	"0"
#define SG18_P638_A1	"0"
#define SG18_P638_A2	"0"
#define SG18_P638_B0	"2D"
#define SG18_P638_B1	"F"
#define SG18_P638_B2	"0"
#define SG18_P638_X0	"1755624848CF51F3209A74B978D9E0547518D2F0E563A6EE4759652BF199892BFBF175C37E4E0726ABFFF10CCB23EAA292F85F286706CF3B2B9397212F6DD1F5EDDD294CFDD9F0459DFF37080FEC2612"
#define SG18_P638_X1	"1A879D2ED904732EC6DA468711A78B088661F67CC580045FC8F2E964EFF69C7DF46D4BAB135385DF79E9BF10DF7F5672B483A6F325B1D17B0345C864030A097D822AE6CD0C97C88D6057212C105D05BE"
#define SG18_P638_X2	"152B2968451C399C716962F3B418022D93E33A083A9E093D1CFFF0A7AC85F279E6FC17AEE2A55B89BCBA9280C69EFA3C19B4EAC0A5598AEED18978DE95DD6291C39A2108DC982418C705116AFAB8406E"
#define SG18_P638_Y0	"1BA3F3688C6CAEB5CDE7E1EC316C4C239F04E21AF8C3A29FEA60D1AD10BE89534DC29EDA41F11ABCEF877FDC72331F6AB3B91F5A9A0EACECAB6185D0F70BF16A200C775AF6FFA8C7FA929D336ABD5933"
#define SG18_P638_Y1	"2341147722E627ACA8F027D929976CE638412C3D310C556D2CCF16DCFED3BB7F5FA5C62278C1D67EEF6C93181BC15B16BC8FFC7AC419077BA7BE92DCDF2A81BD8F98EBB58E70F91EE9B725CB0D84F632"
#define SG18_P638_Y2	"2F32085FC7D6305CB13F58995ACAB1A0B0BBC5C642E0804470F84E0F80E9E1FBA51F8DD11ADDC122EA9A632B276DD9331174A6CBF5E7FBD500A38930DBB26F2C59220C1299B79C4752C8ADF87E1AF255"
#define SG18_P638_R		"6D45960E65595E64AE55954202C604A99543E572A870006483A877DC004A61BE5000000D793FFFFFFFF7000000000001"
#define SG18_P638_H		"87F77ECC6011A73A6F9B3C239413E8278746F3627BECED8355475CE8177053C1DBBEAC0159D2293A4B0F440F9ABCA65386C7305E1888F5A70111BDCE2772A8DA52DE9869A61C0A345DD4AE51209AC13095F27A9636D5B798073A9056163BBB7B3B393CFB5D537C932BFF5EA26FB1455D22D7362313A54DB182588963081F5B011858B919A5BDE89A2F1345AB93F7BE8DD7D186476A6E1B8F3F9A7CA17FF609E65AB7E05B61E57D63A1F73B483C8FAF0C5C1000000A200000000000000000003"
/** @} */
#endif

#if defined(EP_ENDOM) && FP_PRIME == 768
/** @{ */
#define FM18_P768_A0		"0"
#define FM18_P768_A1		"0"
#define FM18_P768_A2		"0"
#define FM18_P768_B0		"-14"
#define FM18_P768_B1		"5"
#define FM18_P768_B2		"0"
#define FM18_P768_X0		"1D930B0B04D7465AB78CA64B2B5DC31F76CA89CABAF298299A7A9F372BD3FF506AC99CB9BE1915BA02C7ED843B32E5B7117F4FF177B9F8EA8E917EA292C020ABF01B8EC7702797F46657A4AC50E0B1BC0E3EFAB4668822FC41DAA3E3E4B54361"
#define FM18_P768_X1		"EC814ED9C93EB3787C1D58406920E3941BF9B39200431A5DD3114F3E9A8202CCCA742B4D0A96D083D11883E4CD4A5AA2FF3D10CAFF789D754C4AF11C09BD453FF379F07C778CFDE0156B87B8A731DD5998715486EBFA0A0F40A7591AC19AF918"
#define FM18_P768_X2		"FCDA64C5662F0E0F0A1FCDCC80BBDCC4B99BAEB06917E0BE604828C636927F9A08A40C184490CE3E5982EDECD2E9D0F93A97BCE43E3C05EC502E781C47866BE70B51F542027C96A2090E96B6428177465C4645F5808ECCDA5A0CB34F689F0E7E"
#define FM18_P768_Y0		"51CC2E24BFC22B4D46B33FF63B91D0B6EF6CDAF5AEFA9B54588F08787362B29489CD18D3EDEEF975B3E07090149EFEEC95455CBD7FADAC43284D4836A2581F81214FF8D7273AA46DF440628B1B4AEBE2BD30809C675EC62B365DE91484BAA6D8"
#define FM18_P768_Y1		"87A1EEC340AB26B14EBE6F2056CE339553090C95A0653432428B62FE34BCCA238F0D067B8E8F2345BC2F46DE68493C75C2ED07C5F2D9B29A6BF9FA730D1C78582819735D7FED671B03C359DECC81765A8A8E1DD16C87801FC3FC40176FB55C5C"
#define FM18_P768_Y2		"DFE9CABA0A20C5FB26091329C60716EC027B828A173120F1AC7BAA5336E97348B26071A022DC0352074F0EA581F63632B6BBBBE9F06CE2762F66087D50D7DB9C96B0192E30F4406104F5D53DCC922A40AEA7600FD79AFB7E2A83350A4D0AD74A"
#define FM18_P768_R			"FFFFFFF27FA00045F4380E5F9EE3795E88D88C72E7B408B61E4CA1FB2558E7C336F40FAAEC98807AF3600C06C0300001"
#define FM18_P768_H			"FFFFFFBC7E20087CAA5905F0B82ABB93AF7E81A53882226042648999C855F369B72CECF33CAFCEE57D8E28C84A08805B59DE451E30AC535A4DD982BCD28F9915B40B200C183FEEB08DC7E199BD1C0BC98FB2653657500B21B5876AA05AA4870EF344801BFE0329F91259BB407D680660A83C30FD7B152124C532AE9C1834BB5967AA84FD428CC94EDE0BBF89981839AB28D48E93F2EA45539030933B28949C5EA287BBE39E92B7641ABED52EC449C1F8561BF845845AF977FFF07688C87D2320CF7D4DDBA602142190F32D2FCD0DFB975E2FF266BD2130ABC252AC90AFF19B742F92924F46054CE84DB1865E82A00003"
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
#if FP_PRIME == 508
			case K18_P508:
				ASSIGN(K18_P508);
				break;
#elif FP_PRIME == 638
			case K18_P638:
				ASSIGN(K18_P638);
				break;
			case SG18_P638:
				ASSIGN(SG18_P638);
				break;
#elif FP_PRIME == 768
			case FM18_P768:
				ASSIGN(FM18_P768);
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
		} else {
			fp3_mul_art(ctx->ep3_frb[0], ctx->ep3_frb[0]);
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
