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
 * Implementation of the prime field modulus manipulation.
 *
 * @ingroup fp
 */

#include "relic_core.h"
#include "relic_fpx.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#if FP_PRIME == 1536
/**
 * Cofactor description of 1536-bit prime modulus.
 */
#define SS_P1536	"83093742908D4D529CEF06C72191A05D5E6073FE861E637D7747C3E52FBB92DAA5DDF3EF1C61F5F70B256802481A36CAFE995FE33CD54014B846751364C0D3B8327D9E45366EA08F1B3446AC23C9D4B656886731A8D05618CFA1A3B202A2445ABA0E77C5F4F00CA1239975A05377084F256DEAA07D21C4CF2A4279BC117603ACB7B10228C3AB8F8C1742D674395701BB02071A88683041D9C4231E8EE982B8DA"
#endif

#if FP_PRIME == 256

/**
 * Random prime modulus for the Brainpool P256r1.
 */
#define BSI_P256		"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_param_get(void) {
	return core_get()->fp_id;
}

void fp_param_set(int param) {
	bn_t t0, t1, t2, p;
	int f[10] = { 0 };

	bn_null(t0);
	bn_null(t1);
	bn_null(t2);
	bn_null(p);

	/* Suppress possible unused parameter warning. */
	(void) f;

	TRY {
		bn_new(t0);
		bn_new(t1);
		bn_new(t2);
		bn_new(p);

		core_get()->fp_id = param;

		switch (param) {
#if FP_PRIME == 158
			case BN_158:
				/* x = 0x4000000031. */
				bn_set_2b(t0, 38);
				bn_add_dig(t0, t0, 0x31);
				fp_prime_set_pairf(t0, EP_BN);
				break;
#elif FP_PRIME == 160
			case SECG_160:
				/* p = 2^160 - 2^31 + 1. */
				f[0] = -1;
				f[1] = -31;
				f[2] = 160;
				fp_prime_set_pmers(f, 3);
				break;
			case SECG_160D:
				/* p = 2^160 - 2^32 - 2^14 - 2^12 - 2^9 - 2^8 - 2^7 - 2^3 - 2^2 - 1.*/
				f[0] = -1;
				f[1] = -2;
				f[2] = -3;
				f[3] = -7;
				f[4] = -8;
				f[5] = -9;
				f[6] = -12;
				f[7] = -14;
				f[8] = -32;
				f[9] = 160;
				fp_prime_set_pmers(f, 10);
				break;
#elif FP_PRIME == 192
			case NIST_192:
				/* p = 2^192 - 2^64 - 1. */
				f[0] = -1;
				f[1] = -64;
				f[2] = 192;
				fp_prime_set_pmers(f, 3);
				break;
			case SECG_192:
				/* p = 2^192 - 2^32 - 2^12 - 2^8 - 2^7 - 2^6 - 2^3 - 1.*/
				f[0] = -1;
				f[1] = -3;
				f[2] = -6;
				f[3] = -7;
				f[4] = -8;
				f[5] = -12;
				f[6] = -32;
				f[7] = 192;
				fp_prime_set_pmers(f, 8);
				break;
#elif FP_PRIME == 221
			case PRIME_22103:
				bn_set_2b(p, 221);
				bn_sub_dig(p, p, 3);
				fp_prime_set_dense(p);
				break;
#elif FP_PRIME == 224
			case NIST_224:
				/* p = 2^224 - 2^96 + 1. */
				f[0] = 1;
				f[1] = -96;
				f[2] = 224;
				fp_prime_set_pmers(f, 3);
				break;
			case SECG_224:
				/* p = 2^224 - 2^32 - 2^12 - 2^11 - 2^9 - 2^7 - 2^4 - 2 - 1.*/
				f[0] = -1;
				f[1] = -1;
				f[2] = -4;
				f[3] = -7;
				f[4] = -9;
				f[5] = -11;
				f[6] = -12;
				f[7] = -32;
				f[8] = 224;
				fp_prime_set_pmers(f, 9);
				break;
#elif FP_PRIME == 226
			case PRIME_22605:
				bn_set_2b(p, 226);
				bn_sub_dig(p, p, 5);
				fp_prime_set_dense(p);
				break;
#elif FP_PRIME == 251
			case PRIME_25109:
				bn_set_2b(p, 251);
				bn_sub_dig(p, p, 9);
				fp_prime_set_dense(p);
				break;
#elif FP_PRIME == 254
			case BN_254:
				/* x = -(2^62 + 2^55 + 1). */
				bn_set_2b(t0, 62);
				bn_set_bit(t0, 55, 1);
				bn_add_dig(t0, t0, 1);
				bn_neg(t0, t0);
				fp_prime_set_pairf(t0, EP_BN);
				break;
#elif FP_PRIME == 255
			case PRIME_25519:
				bn_set_2b(p, 255);
				bn_sub_dig(p, p, 19);
				fp_prime_set_dense(p);
				break;
#elif FP_PRIME == 256
			case NIST_256:
				/* p = 2^256 - 2^224 + 2^192 + 2^96 - 1. */
				f[0] = -1;
				f[1] = 96;
				f[2] = 192;
				f[3] = -224;
				f[4] = 256;
				fp_prime_set_pmers(f, 5);
				break;
			case BSI_256:
				bn_read_str(p, BSI_P256, strlen(BSI_P256), 16);
				fp_prime_set_dense(p);
				break;
			case SECG_256:
				/* p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1. */
				f[0] = -1;
				f[1] = -4;
				f[2] = -6;
				f[3] = -7;
				f[4] = -8;
				f[5] = -9;
				f[6] = -32;
				f[7] = 256;
				fp_prime_set_pmers(f, 8);
				break;
			case BN_256:
				/* x = -0x600000000000219B. */
				bn_set_2b(t0, 62);
				bn_set_bit(t0, 61, 1);
				bn_set_dig(t1, 0x21);
				bn_lsh(t1, t1, 8);
				bn_add(t0, t0, t1);
				bn_add_dig(t0, t0, 0x9B);
				bn_neg(t0, t0);
				fp_prime_set_pairf(t0, EP_BN);
				break;
#elif FP_PRIME == 381
			case B12_381:
				/* x = -(2^63 + 2^62 + 2^60 + 2^57 + 2^48 + 2^16). */
				bn_set_2b(t0, 63);
				bn_set_bit(t0, 62, 1);
				bn_set_bit(t0, 60, 1);
				bn_set_bit(t0, 57, 1);
				bn_set_bit(t0, 48, 1);
				bn_set_bit(t0, 16, 1);
				bn_neg(t0, t0);
				fp_prime_set_pairf(t0, EP_B12);
				break;
#elif FP_PRIME == 382
			case PRIME_382105:
				bn_set_2b(p, 382);
				bn_sub_dig(p, p, 105);
				fp_prime_set_dense(p);
				break;
			case BN_382:
				/* x = -(2^94 + 2^78 + 2^67 + 2^64 + 2^48 + 1). */
				bn_set_2b(t0, 94);
				bn_set_bit(t0, 78, 1);
				bn_set_bit(t0, 67, 1);
				bn_set_bit(t0, 64, 1);
				bn_set_bit(t0, 48, 1);
				bn_add_dig(t0, t0, 1);
				bn_neg(t0, t0);
				fp_prime_set_pairf(t0, EP_BN);
				break;
#elif FP_PRIME == 383
			case PRIME_383187:
				bn_set_2b(p, 383);
				bn_sub_dig(p, p, 187);
				fp_prime_set_dense(p);
				break;
#elif FP_PRIME == 384
			case NIST_384:
				/* p = 2^384 - 2^128 - 2^96 + 2^32 - 1. */
				f[0] = -1;
				f[1] = 32;
				f[2] = -96;
				f[3] = -128;
				f[4] = 384;
				fp_prime_set_pmers(f, 5);
				break;
#elif FP_PRIME == 446
			case BN_446:
				/* x = 2^110 + 2^36 + 1. */
				bn_set_2b(t0, 110);
				bn_set_bit(t0, 36, 1);
				bn_add_dig(t0, t0, 1);
				fp_prime_set_pairf(t0, EP_BN);
				break;
			case B12_446:
				/* x = -(2^75 - 2^73 + 2^63 + 2^57 + 2^50 + 2^17 + 1). */
				bn_set_2b(t0, 75);
				bn_set_bit(t0, 63, 1);
				bn_set_bit(t0, 57, 1);
				bn_set_bit(t0, 50, 1);
				bn_set_bit(t0, 17, 1);
				bn_add_dig(t0, t0, 1);
				bn_set_2b(t1, 73);
				bn_sub(t0, t0, t1);
				bn_neg(t0, t0);
				fp_prime_set_pairf(t0, EP_B12);
				break;
#elif FP_PRIME == 455
			case B12_455:
				/* x = 2^76 + 2^53 + 2^31 + 2^11. */
				bn_set_2b(t0, 76);
				bn_set_bit(t0, 53, 1);
				bn_set_bit(t0, 31, 1);
				bn_set_bit(t0, 11, 1);
				fp_prime_set_pairf(t0, EP_B12);
				break;
#elif FP_PRIME == 477
			case B24_477:
				/* x = -2^48 + 2^45 + 2^31 - 2^7. */
				bn_set_2b(t0, 48);
				bn_set_2b(t1, 45);
				bn_sub(t0, t0, t1);
				bn_set_2b(t1, 31);
				bn_sub(t0, t0, t1);
				bn_set_2b(t1, 7);
				bn_add(t0, t0, t1);
				bn_neg(t0, t0);
				/* p = (u - 1)^2 * (u^8 - u^4 + 1) div 3 + u. */
				bn_sub_dig(p, t0, 1);
				bn_sqr(p, p);
				bn_sqr(t1, t0);
				bn_sqr(t1, t1);
				bn_sqr(t2, t1);
				bn_sub(t2, t2, t1);
				bn_add_dig(t2, t2, 1);
				bn_mul(p, p, t2);
				bn_div_dig(p, p, 3);
				bn_add(p, p, t0);
				fp_prime_set_dense(p);
				break;
#elif FP_PRIME == 508
			case KSS_508:
				/* x = -(2^64 + 2^51 - 2^46 - 2^12). */
				bn_set_2b(t0, 64);
				bn_set_2b(t1, 51);
				bn_add(t0, t0, t1);
				bn_set_2b(t1, 46);
				bn_sub(t0, t0, t1);
				bn_set_2b(t1, 12);
				bn_sub(t0, t0, t1);
				bn_neg(t1, t1);
				/* h = (49*u^2 + 245 * u + 343)/3 */
				bn_mul_dig(p, t0, 245);
				bn_add_dig(p, p, 200);
				bn_add_dig(p, p, 143);
				bn_sqr(t1, t0);
				bn_mul_dig(t2, t1, 49);
				bn_add(p, p, t2);
				bn_div_dig(p, p, 3);
				/* n = (u^6 + 37 * u^3 + 343)/343. */
				bn_mul(t1, t1, t0);
				bn_mul_dig(t2, t1, 37);
				bn_sqr(t1, t1);
				bn_add(t2, t2, t1);
				bn_add_dig(t2, t2, 200);
				bn_add_dig(t2, t2, 143);
				bn_div_dig(t2, t2, 49);
				bn_div_dig(t2, t2, 7);
				bn_mul(p, p, t2);
				/* t = (u^4 + 16 * u + 7)/7. */
				bn_mul_dig(t1, t0, 16);
				bn_add_dig(t1, t1, 7);
				bn_sqr(t2, t0);
				bn_sqr(t2, t2);
				bn_add(t2, t2, t1);
				bn_div_dig(t2, t2, 7);
				bn_add(p, p, t2);
				bn_sub_dig(p, p, 1);
				fp_prime_set_dense(p);
				break;
#elif FP_PRIME == 511
			case OT_511:
				bn_set_2b(t0, 52);
				bn_add_dig(t0, t0, 0xAB);
				bn_lsh(t0, t0, 12);
				fp_prime_set_pairf(t0, EP_OT);
				break;
			case PRIME_511187:
				bn_set_2b(p, 511);
				bn_sub_dig(p, p, 187);
				fp_prime_set_dense(p);
				break;
#elif FP_PRIME == 521
			case NIST_521:
				/* p = 2^521 - 1. */
				f[0] = -1;
				f[1] = 521;
				fp_prime_set_pmers(f, 2);
				break;
#elif FP_PRIME == 638
			case BN_638:
				/* x = 2^158 - 2^128 - 2^68 + 1. */
				bn_set_2b(t0, 158);
				bn_set_2b(t1, 128);
				bn_sub(t0, t0, t1);
				bn_set_2b(t1, 68);
				bn_sub(t0, t0, t1);
				bn_add_dig(t0, t0, 1);
				fp_prime_set_pairf(t0, EP_BN);
				break;
			case B12_638:
				/* x = -2^107 + 2^105 + 2^93 + 2^5. */
				bn_set_2b(t0, 107);
				bn_set_2b(t1, 105);
				bn_sub(t0, t0, t1);
				bn_set_2b(t1, 93);
				bn_sub(t0, t0, t1);
				bn_set_2b(t1, 5);
				bn_sub(t0, t0, t1);
				bn_neg(t0, t0);
				fp_prime_set_pairf(t0, EP_B12);
				break;
#elif FP_PRIME == 1536
			case SS_1536:
				/* x = 2^255 + 2^41 + 1. */
				bn_set_2b(t0, 255);
				bn_set_bit(t0, 41, 1);
				bn_add_dig(t0, t0, 1);
				bn_read_str(p, SS_P1536, strlen(SS_P1536), 16);
				bn_mul(p, p, t0);
				bn_dbl(p, p);
				bn_sub_dig(p, p, 1);
				fp_prime_set_dense(p);
				break;
#else
			default:
				fp_param_set_any_dense();
				core_get()->fp_id = 0;
				break;
#endif
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(t0);
		bn_free(t1);
		bn_free(t2);
		bn_free(p);
	}
}

int fp_param_set_any(void) {
#if FP_PRIME == 158
	fp_param_set(BN_158);
#elif FP_PRIME == 160
	fp_param_set(SECG_160);
#elif FP_PRIME == 192
	fp_param_set(NIST_192);
#elif FP_PRIME == 221
	fp_param_set(PRIME_22103);
#elif FP_PRIME == 224
	fp_param_set(NIST_224);
#elif FP_PRIME == 226
	fp_param_set(PRIME_22605);
#elif FP_PRIME == 254
	fp_param_set(BN_254);
#elif FP_PRIME == 251
	fp_param_set(PRIME_25109);
#elif FP_PRIME == 255
	fp_param_set(PRIME_25519);
#elif FP_PRIME == 256
#ifdef FP_PMERS
	fp_param_set(SECG_256);
#else
	fp_param_set(BN_256);
#endif
#elif FP_PRIME == 381
	fp_param_set(B12_381);
#elif FP_PRIME == 382
	fp_param_set(BN_382);
#elif FP_PRIME == 383
	fp_param_set(PRIME_383187);
#elif FP_PRIME == 384
	fp_param_set(NIST_384);
#elif FP_PRIME == 446
#ifdef FP_QNRES
	fp_param_set(B12_446);
#else
	fp_param_set(BN_446);
#endif
#elif FP_PRIME == 455
	fp_param_set(B12_455);
#elif FP_PRIME == 477
	fp_param_set(B24_477);
#elif FP_PRIME == 508
	fp_param_set(KSS_508);
#elif FP_PRIME == 511
	fp_param_set(OT_511);
#elif FP_PRIME == 521
	fp_param_set(NIST_521);
#elif FP_PRIME == 638
#ifdef FP_QNRES
	fp_param_set(B12_638);
#else
	fp_param_set(BN_638);
#endif
#elif FP_PRIME == 1536
	fp_param_set(SS_1536);
#else
	return fp_param_set_any_dense();
#endif
	return RLC_OK;
}

int fp_param_set_any_dense(void) {
	bn_t p;
	int result = RLC_OK;

	bn_null(p);

	TRY {
		bn_new(p);
#ifdef FP_QNRES
		do {
			bn_gen_prime(p, RLC_FP_BITS);
		} while ((p->dp[0] & 0x7) != 3);
#else
		bn_gen_prime(p, RLC_FP_BITS);
#endif
		if (!bn_is_prime(p)) {
			result = RLC_ERR;
		} else {
			fp_prime_set_dense(p);
		}
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		bn_free(p);
	}
	return result;
}

int fp_param_set_any_pmers(void) {
#if FP_PRIME == 160
	fp_param_set(SECG_160);
#elif FP_PRIME == 192
	fp_param_set(NIST_192);
#elif FP_PRIME == 224
	fp_param_set(NIST_224);
#elif FP_PRIME == 256
	fp_param_set(NIST_256);
#elif FP_PRIME == 384
	fp_param_set(NIST_384);
#elif FP_PRIME == 521
	fp_param_set(NIST_521);
#else
	return RLC_ERR;
#endif
	return RLC_OK;
}

int fp_param_set_any_tower(void) {
#if FP_PRIME == 158
	fp_param_set(BN_158);
#elif FP_PRIME == 254
	fp_param_set(BN_254);
#elif FP_PRIME == 256
	fp_param_set(BN_256);
#elif FP_PRIME == 381
	fp_param_set(B12_381);
#elif FP_PRIME == 382
	fp_param_set(BN_382);
#elif FP_PRIME == 446
#ifdef FP_QNRES
	fp_param_set(B12_446);
#else
	fp_param_set(BN_446);
#endif
#elif FP_PRIME == 455
	fp_param_set(B12_455);
#elif FP_PRIME == 477
	fp_param_set(B24_477);
#elif FP_PRIME == 508
	fp_param_set(KSS_508);
#elif FP_PRIME == 511
	fp_param_set(OT_511);
#elif FP_PRIME == 638
#ifdef FP_QNRES
	fp_param_set(B12_638);
#else
	fp_param_set(BN_638);
#endif
#elif FP_PRIME == 1536
	fp_param_set(SS_1536);
#else
	do {
		/* Since we have to generate a prime number, pick a nice towering. */
		fp_param_set_any_dense();
	} while (fp_prime_get_mod8() == 1 || fp_prime_get_mod8() == 5);
#endif

	return RLC_OK;
}

void fp_param_print(void) {
	util_banner("Prime modulus:", 0);
	util_print("   ");
#if ALLOC == AUTO
	fp_print(fp_prime_get());
#else
	fp_print((const fp_t)fp_prime_get());
#endif
}
