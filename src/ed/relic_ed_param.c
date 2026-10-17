/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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
 * Implementation of the Edwards elliptic curve parameters.
 *
 * @ingroup ed
 */

#include "relic_core.h"

#if FP_PRIME == 255
/**
 * Parameters for the Ed25519 prime elliptic curve.
 */
/** @{ */
#define CURVE_ED25519_A	"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC"
#define CURVE_ED25519_D "52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3"
#define CURVE_ED25519_X "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
#define CURVE_ED25519_Y	"6666666666666666666666666666666666666666666666666666666666666658"
#define CURVE_ED25519_R "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"
#define CURVE_ED25519_H "0000000000000000000000000000000000000000000000000000000000000008"
/** @} */
#elif FP_PRIME == 448
/**
 * Parameters for the Ed448 prime elliptic curve from RFC 8032.
 */
/** @{ */
#define CURVE_ED448_A	"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
#define CURVE_ED448_D	"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756"
#define CURVE_ED448_X	"4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E"
#define CURVE_ED448_Y	"693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14"
#define CURVE_ED448_R	"3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3"
#define CURVE_ED448_H	"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004"
/** @} */
#elif FP_PRIME == 521
/**
 * Parameters for the E-521 prime elliptic curve.
 */
/** @{ */
#define CURVE_ED521_A	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
#define CURVE_ED521_D	"1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA4331"
#define CURVE_ED521_X	"0752CB45C48648B189DF90CB2296B2878A3BFD9F42FC6C818EC8BF3C9C0C6203913F6ECC5CCC72434B1AE949D568FC99C6059D0FB13364838AA302A940A2F19BA6C"
#define CURVE_ED521_Y	"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000C"
#define CURVE_ED521_R	"07FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD15B6C64746FC85F736B8AF5E7EC53F04FBD8C4569A8F1F4540EA2435F5180D6B"
#define CURVE_ED521_H	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004"
/** @} */
#endif

/**
 * Assigns a set of ordinary elliptic curve parameters.
 *
 * @param[in] CURVE		- the curve parameters to assign.
 * @param[in] FIELD		- the finite field identifier.
 */
#define ED_ASSIGN(CURVE, FIELD)												\
	fp_param_set(FIELD);													\
	RLC_GET(str, CURVE##_A, sizeof(CURVE##_A));								\
	fp_read_str(core_get()->ed_a, str, strlen(str), 16);					\
	RLC_GET(str, CURVE##_D, sizeof(CURVE##_D));								\
	fp_read_str(core_get()->ed_d, str, strlen(str), 16);					\
	RLC_GET(str, CURVE##_X, sizeof(CURVE##_X));								\
	fp_read_str(g->x, str, strlen(str), 16);								\
	RLC_GET(str, CURVE##_Y, sizeof(CURVE##_Y));								\
	fp_read_str(g->y, str, strlen(str), 16);								\
	fp_set_dig(g->z, 1);													\
	RLC_GET(str, CURVE##_R, sizeof(CURVE##_R));								\
	bn_read_str(r, str, strlen(str), 16);									\
	RLC_GET(str, CURVE##_H, sizeof(CURVE##_H));								\
	bn_read_str(h, str, strlen(str), 16);

void ed_param_set(int param) {
	ctx_t *ctx = core_get();
	char str[2 * RLC_FP_BYTES + 2];

	ed_t g;
	bn_t r;
	bn_t h;

	ed_null(g);
	bn_null_all(r, h);

	RLC_TRY {
		ed_new(g);
		bn_new_all(r, h);

		ctx->ed_id = 0;

		switch (param) {
#if FP_PRIME == 255
			case CURVE_ED25519:
				ED_ASSIGN(CURVE_ED25519, PRIME_25519);
				break;
#elif FP_PRIME == 448
			case CURVE_ED448:
				ED_ASSIGN(CURVE_ED448, PRIME_448);
				break;
#elif FP_PRIME == 521
			case CURVE_ED521:
				ED_ASSIGN(CURVE_ED521, NIST_521);
				break;
#endif
			default:
				(void)str;
				/* Leave the curve unset, and the rest well defined. */
				param = 0;
				ed_set_infty(g);
				bn_zero(r);
				bn_zero(h);
				RLC_THROW(ERR_NO_VALID);
				break;
		}
		fp_set_dig(g->z, 1);
		fp_neg(g->z, g->z);
		fp_neg(g->z, g->z);
#if ED_ADD == ED_EXTND
		fp_mul(g->t, g->x, g->y);
#endif
		g->coord = EC_AFFIN;

		bn_copy(&ctx->ed_h, h);
		bn_copy(&ctx->ed_r, r);
		ed_copy(&ctx->ed_g, g);

#ifdef ED_PRECO
		for (int i = 0; i < RLC_ED_TABLE; i++) {
			ctx->ed_ptr[i] = &(ctx->ed_pre[i]);
		}
		ed_mul_pre((ed_t *)ed_curve_get_tab(), &ctx->ed_g);
#endif
		ctx->ed_id = param;

		/* Compute the constants for hashing to the curve. */
		if (fp_prime_get_mod8() == 5) {
			/* p = 5 mod 8: Elligator 2 through Curve25519. */
			if (param != CURVE_ED25519) {
				RLC_THROW(ERR_NO_VALID);
			}
			h->used = RLC_FP_DIGS;
			h->sign = RLC_POS;
			dv_copy(h->dp, fp_prime_get(), RLC_FP_DIGS); /* p */
			bn_add_dig(h, h, 3);                         /* p + 3 */
			bn_rsh(h, h, 3);                             /* (p + 3) / 8 */
			/* compute 2^((p+3)/8) */
			fp_set_dig(ctx->ed_map_c[0], 2);
			fp_exp(ctx->ed_map_c[0], ctx->ed_map_c[0], h);

			/* compute sqrt(-1) */
			fp_set_dig(ctx->ed_map_c[1], 1);
			fp_neg(ctx->ed_map_c[1], ctx->ed_map_c[1]);
			if (!fp_srt(ctx->ed_map_c[1], ctx->ed_map_c[1])) {
				/* should never happen because 2adicity > 1 */
				RLC_THROW(ERR_NO_VALID);
			}

			/* compute sqrt(-486664) for mapping curve25519 -> edwards25519 */
			fp_read_str(ctx->ed_map_c[3], "486662", 6, 10);
			fp_add_dig(ctx->ed_map_c[2], ctx->ed_map_c[3], 2);
			fp_neg(ctx->ed_map_c[2], ctx->ed_map_c[2]);
			if (!fp_srt(ctx->ed_map_c[2], ctx->ed_map_c[2])) {
				RLC_THROW(ERR_NO_VALID);
			}
			fp_prime_back(h, ctx->ed_map_c[2]);
			/* make sure sgn0(ctx->ed_map_c[2]) == 0 */
			if (bn_get_bit(h, 0) != 0) {
				fp_neg(ctx->ed_map_c[2], ctx->ed_map_c[2]);
			}
		} else if (fp_prime_get_mod8() % 4 == 3) {
			/* p = 3 mod 4: Elligator 2 on the Montgomery curve
			 * K * t^2 = s^3 + J * s^2 + s, with J = 2(a + d)/(a - d) and
			 * K = 4/(a - d), stored as J/K = (a + d)/2, 1/K^2 and K. */
			fp_add(ctx->ed_map_c[0], ctx->ed_a, ctx->ed_d);
			fp_hlv(ctx->ed_map_c[0], ctx->ed_map_c[0]);
			fp_sub(ctx->ed_map_c[2], ctx->ed_a, ctx->ed_d);
			fp_inv(ctx->ed_map_c[2], ctx->ed_map_c[2]);
			fp_dbl(ctx->ed_map_c[2], ctx->ed_map_c[2]);
			fp_dbl(ctx->ed_map_c[2], ctx->ed_map_c[2]);
			fp_sqr(ctx->ed_map_c[1], ctx->ed_map_c[2]);
			fp_inv(ctx->ed_map_c[1], ctx->ed_map_c[1]);
		} else {
			RLC_THROW(ERR_NO_VALID);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(r, h);
		ed_free(g);
	}
}

int ed_param_set_any(void) {
	int r = RLC_OK;
#if FP_PRIME == 255
	ed_param_set(CURVE_ED25519);
#elif FP_PRIME == 448
	ed_param_set(CURVE_ED448);
#elif FP_PRIME == 521
	ed_param_set(CURVE_ED521);
#else
	r = RLC_ERR;
#endif
	return r;
}

int ed_param_get(void) {
	return core_get()->ed_id;
}

int ed_param_level(void) {
	switch (ed_param_get()) {
		case CURVE_ED25519:
			return 128;
		case CURVE_ED448:
			return 224;
		case CURVE_ED521:
			return 256;
	}
	return 0;
}

void ed_param_print(void) {
	switch (ed_param_get()) {
		case CURVE_ED25519:
			util_banner("Curve ED25519:", 0);
			break;
		case CURVE_ED448:
			util_banner("Curve ED448:", 0);
			break;
		case CURVE_ED521:
			util_banner("Curve ED521:", 0);
			break;
	}
}
