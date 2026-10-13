/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Tests for the block cipher module.
 *
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

/**
 * Plaintext of the CBC vectors of NIST SP 800-38A, Appendix F.2.
 */
static const uint8_t aes_pt[64] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
	0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46,
	0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
	0xe6, 0x6c, 0x37, 0x10
};

/**
 * Initialization vector of the CBC vectors of NIST SP 800-38A.
 */
static const uint8_t aes_iv[RLC_BC_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f
};

/**
 * AES-128, AES-192 and AES-256 keys of NIST SP 800-38A, F.2.1, F.2.3, F.2.5.
 */
static const uint8_t aes_key[3][32] = {
	{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c
	}, {
		0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
		0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
	}, {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
		0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
	}
};

/**
 * Ciphertexts of NIST SP 800-38A, followed by the encryption of the block of
 * PKCS#7 padding that the plaintext of 64 bytes gets.
 */
static const uint8_t aes_ct[3][80] = {
	{
		0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b,
		0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
		0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8,
		0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
		0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30,
		0x75, 0x86, 0xe1, 0xa7, 0x8c, 0xb8, 0x28, 0x07, 0x23, 0x0e, 0x13, 0x21,
		0xd3, 0xfa, 0xe0, 0x0d, 0x18, 0xcc, 0x20, 0x12
	}, {
		0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18, 0x3a,
		0x9f, 0xa0, 0x71, 0xe8, 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
		0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a, 0x57, 0x1b, 0x24, 0x20,
		0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
		0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81, 0xd9, 0x20, 0xa9, 0xe6,
		0x4f, 0x56, 0x15, 0xcd, 0x61, 0x2c, 0xcd, 0x79, 0x22, 0x4b, 0x35, 0x09,
		0x35, 0xd4, 0x5d, 0xd6, 0xa9, 0x8f, 0x81, 0x76
	}, {
		0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb,
		0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
		0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d, 0x39, 0xf2, 0x33, 0x69,
		0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
		0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07,
		0x8c, 0x6a, 0x9d, 0x1b, 0x3f, 0x46, 0x17, 0x96, 0xd6, 0xb0, 0xd6, 0xb2,
		0xe0, 0xc2, 0xa7, 0x2b, 0x4d, 0x80, 0xe6, 0x44
	}
};

static int aes(void) {
	int code = RLC_ERR;
	uint8_t key[32], iv[RLC_BC_LEN], in[64], out[96], res[96];
	size_t lens[] = { 0, 1, 15, 16, 17, 31, 32, 33, 64 };
	size_t out_len, res_len;

	TEST_ONCE("aes-cbc encryption is correct with known-answer vectors") {
		for (int j = 0; j < 3; j++) {
			out_len = sizeof(out);
			TEST_ASSERT(bc_aes_cbc_enc(out, &out_len, aes_pt, 64, aes_key[j],
					16 + 8 * j, aes_iv) == RLC_OK, end);
			TEST_ASSERT(out_len == 80, end);
			TEST_ASSERT(memcmp(out, aes_ct[j], 80) == 0, end);
			res_len = sizeof(res);
			TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, aes_ct[j], 80,
					aes_key[j], 16 + 8 * j, aes_iv) == RLC_OK, end);
			TEST_ASSERT(res_len == 64, end);
			TEST_ASSERT(memcmp(res, aes_pt, 64) == 0, end);
		}
	} TEST_END;

	TEST_CASE("aes-cbc encryption/decryption is correct") {
		rand_bytes(key, sizeof(key));
		rand_bytes(iv, sizeof(iv));
		rand_bytes(in, sizeof(in));
		for (int j = 0; j < (int)(sizeof(lens) / sizeof(lens[0])); j++) {
			for (size_t k = 16; k <= 32; k += 8) {
				out_len = sizeof(out);
				TEST_ASSERT(bc_aes_cbc_enc(out, &out_len, in, lens[j], key, k,
						iv) == RLC_OK, end);
				TEST_ASSERT(out_len == lens[j] - lens[j] % 16 + 16, end);
				res_len = sizeof(res);
				TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, out, out_len, key, k,
						iv) == RLC_OK, end);
				TEST_ASSERT(res_len == lens[j], end);
				TEST_ASSERT(memcmp(res, in, lens[j]) == 0, end);
				/* The same works in place. */
				memcpy(res, in, lens[j]);
				res_len = sizeof(res);
				TEST_ASSERT(bc_aes_cbc_enc(res, &res_len, res, lens[j], key, k,
						iv) == RLC_OK, end);
				TEST_ASSERT(res_len == out_len, end);
				TEST_ASSERT(memcmp(res, out, out_len) == 0, end);
				TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, res, res_len, key, k,
						iv) == RLC_OK, end);
				TEST_ASSERT(res_len == lens[j], end);
				TEST_ASSERT(memcmp(res, in, lens[j]) == 0, end);
			}
		}
	} TEST_END;

	TEST_ONCE("aes-cbc rejects invalid keys, lengths and buffers") {
		rand_bytes(key, sizeof(key));
		rand_bytes(iv, sizeof(iv));
		rand_bytes(in, sizeof(in));
		for (size_t k = 0; k <= 33; k++) {
			if (k != 16 && k != 24 && k != 32) {
				out_len = sizeof(out);
				TEST_ASSERT(bc_aes_cbc_enc(out, &out_len, in, 16, key, k,
						iv) == RLC_ERR, end);
				res_len = sizeof(res);
				TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, in, 16, key, k,
						iv) == RLC_ERR, end);
			}
		}
		/* Ciphertexts must be a positive number of blocks. */
		for (size_t l = 0; l <= 33; l++) {
			if (l % 16 != 0 || l == 0) {
				res_len = sizeof(res);
				TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, in, l, key, 16,
						iv) == RLC_ERR, end);
			}
		}
		/* Outputs of 17 bytes need two blocks. */
		out_len = 31;
		TEST_ASSERT(bc_aes_cbc_enc(out, &out_len, in, 17, key, 16, iv) ==
				RLC_ERR, end);
		out_len = 32;
		TEST_ASSERT(bc_aes_cbc_enc(out, &out_len, in, 17, key, 16, iv) ==
				RLC_OK, end);
		res_len = 16;
		TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, out, out_len, key, 16,
				iv) == RLC_ERR, end);
		res_len = 17;
		TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, out, out_len, key, 16,
				iv) == RLC_OK && res_len == 17, end);
	} TEST_END;

	TEST_ONCE("aes-cbc rejects invalid padding without leaking plaintext") {
		uint8_t pads[][2] = { { 0x01, 0x00 }, { 0x01, 0x11 }, { 0x01, 0x02 },
			{ 0xFF, 0x10 } };
		rand_bytes(key, sizeof(key));
		rand_bytes(iv, sizeof(iv));
		for (int j = 0; j < 4; j++) {
			/* Encrypting two blocks gives C1 | C2 | C3, where decrypting only
			 * C1 | C2 leaves the second plaintext block as the padding. */
			memset(in, 0x42, 32);
			in[30] = pads[j][0];
			in[31] = pads[j][1];
			out_len = sizeof(out);
			TEST_ASSERT(bc_aes_cbc_enc(out, &out_len, in, 32, key, 16, iv) ==
					RLC_OK, end);
			res_len = sizeof(res);
			memset(res, 0x55, sizeof(res));
			TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, out, 32, key, 16, iv) ==
					RLC_ERR, end);
			for (int l = 0; l < 16; l++) {
				TEST_ASSERT(res[l] == 0, end);
			}
		}
		/* A last byte of 01 is valid padding. */
		in[31] = 0x01;
		out_len = sizeof(out);
		TEST_ASSERT(bc_aes_cbc_enc(out, &out_len, in, 32, key, 16, iv) ==
				RLC_OK, end);
		res_len = sizeof(res);
		TEST_ASSERT(bc_aes_cbc_dec(res, &res_len, out, 32, key, 16, iv) ==
				RLC_OK && res_len == 31, end);
		TEST_ASSERT(memcmp(res, in, 31) == 0, end);
	} TEST_END;

	code = RLC_OK;
  end:
	return code;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the BC module:\n", 0);

	if (aes() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
