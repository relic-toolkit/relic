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
 * Tests for implementation of cryptographic protocols based on integer factorization.
 *
 * @version $Id$
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

static int rsa(void) {
	int code = RLC_ERR;
	rsa_t pub, prv;
	uint8_t in[10], out[RLC_BN_BITS / 8 + 1], h[RLC_MD_LEN];
	size_t il, ol;
	int result;

	rsa_null(pub);
	rsa_null(prv);

	RLC_TRY {
		rsa_new(pub);
		rsa_new(prv);

		result = cp_rsa_gen(pub, prv, RLC_BN_BITS);

		TEST_CASE("rsa encryption/decryption is correct") {
			TEST_ASSERT(result == RLC_OK, end);
			il = 10;
			ol = RLC_BN_BITS / 8 + 1;
			rand_bytes(in, il);
			TEST_ASSERT(cp_rsa_enc(out, &ol, in, il, pub) == RLC_OK, end);
			TEST_ASSERT(cp_rsa_dec(out, &ol, out, ol, prv) == RLC_OK, end);
			TEST_ASSERT(memcmp(in, out, ol) == 0, end);
		} TEST_END;

		result = cp_rsa_gen(pub, prv, RLC_BN_BITS);

		TEST_CASE("rsa signature/verification is correct") {
			TEST_ASSERT(result == RLC_OK, end);
			il = 10;
			ol = RLC_BN_BITS / 8 + 1;
			rand_bytes(in, il);
			TEST_ASSERT(cp_rsa_sig(out, &ol, in, il, 0, prv) == RLC_OK, end);
			TEST_ASSERT(cp_rsa_ver(out, ol, in, il, 0, pub) == 1, end);
			md_map(h, in, il);
			TEST_ASSERT(cp_rsa_sig(out, &ol, h, RLC_MD_LEN, 1, prv) == RLC_OK, end);
			TEST_ASSERT(cp_rsa_ver(out, ol, h, RLC_MD_LEN, 1, pub) == 1, end);
		} TEST_END;

		/* A modulus of 8k + 1 bits has encoded messages one byte shorter. */
		result = cp_rsa_gen(pub, prv, RLC_BN_BITS - 7);

		TEST_CASE("rsa key generation has the requested length") {
			TEST_ASSERT(result == RLC_OK, end);
			TEST_ASSERT(bn_bits(pub->crt->n) == RLC_BN_BITS - 7, end);
			TEST_ASSERT(bn_cmp(pub->crt->n, prv->crt->n) == RLC_EQ, end);
			TEST_ASSERT(bn_cmp(pub->e, prv->e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("rsa is correct with a modulus of 8k + 1 bits") {
			TEST_ASSERT(result == RLC_OK, end);
			il = 10;
			ol = RLC_BN_BITS / 8 + 1;
			rand_bytes(in, il);
			TEST_ASSERT(cp_rsa_sig(out, &ol, in, il, 0, prv) == RLC_OK, end);
			TEST_ASSERT(cp_rsa_ver(out, ol, in, il, 0, pub) == 1, end);
			ol = RLC_BN_BITS / 8 + 1;
			rand_bytes(in, il);
			TEST_ASSERT(cp_rsa_enc(out, &ol, in, il, pub) == RLC_OK, end);
			TEST_ASSERT(cp_rsa_dec(out, &ol, out, ol, prv) == RLC_OK, end);
			TEST_ASSERT(memcmp(in, out, ol) == 0, end);
		} TEST_END;
	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	rsa_free(pub);
	rsa_free(prv);
	return code;
}

static int rabin(void) {
	int code = RLC_ERR;
	rabin_t pub, prv;
	uint8_t in[10];
	uint8_t out[RLC_BN_BITS / 8 + 1];
	size_t in_len, out_len;
	int result;

	rabin_null(pub);
	rabin_null(prv);

	RLC_TRY {
		rabin_new(pub);
		rabin_new(prv);

		result = cp_rabin_gen(pub, prv, RLC_BN_BITS);

		TEST_CASE("rabin encryption/decryption is correct") {
			TEST_ASSERT(result == RLC_OK, end);
			in_len = 10;
			out_len = RLC_BN_BITS / 8 + 1;
			rand_bytes(in, in_len);
			TEST_ASSERT(cp_rabin_enc(out, &out_len, in, in_len, pub) == RLC_OK,
					end);
			TEST_ASSERT(cp_rabin_dec(out, &out_len, out, out_len,
							prv) == RLC_OK, end);
			TEST_ASSERT(memcmp(in, out, out_len) == 0, end);
		} TEST_END;
	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	rabin_free(pub);
	rabin_free(prv);
	return code;
}

static int benaloh(void) {
	int code = RLC_ERR;
	bdpe_t pub, prv;
	bn_t a, b;
	dig_t in, out;
	uint8_t buf[RLC_BN_BITS / 8 + 1];
	size_t len;
	int result;
	dig_t prime = 0xFB;

	bn_null(a);
	bn_null(b);
	bdpe_null(pub);
	bdpe_null(prv);

	RLC_TRY {
		bn_new(a);
		bn_new(b);
		bdpe_new(pub);
		bdpe_new(prv);

		result = cp_bdpe_gen(pub, prv, prime, RLC_BN_BITS);

		TEST_CASE("benaloh encryption/decryption is correct") {
			TEST_ASSERT(result == RLC_OK, end);
			len = RLC_BN_BITS / 8 + 1;
			rand_bytes(buf, 1);
			in = buf[0] % prime;
			TEST_ASSERT(cp_bdpe_enc(buf, &len, in, pub) == RLC_OK, end);
			TEST_ASSERT(cp_bdpe_dec(&out, buf, len, prv) == RLC_OK, end);
			TEST_ASSERT(in == out, end);
		} TEST_END;

		TEST_CASE("benaloh encryption/decryption is homomorphic") {
			TEST_ASSERT(result == RLC_OK, end);
			len = RLC_BN_BITS / 8 + 1;
			rand_bytes(buf, 1);
			in = buf[0] % prime;
			TEST_ASSERT(cp_bdpe_enc(buf, &len, in, pub) == RLC_OK, end);
			bn_read_bin(a, buf, len);
			rand_bytes(buf, 1);
			out = (buf[0] % prime);
			in = (in + out) % prime;
			TEST_ASSERT(cp_bdpe_enc(buf, &len, out, pub) == RLC_OK, end);
			bn_read_bin(b, buf, len);
			bn_mul(a, a, b);
			bn_mod(a, a, pub->n);
			len = bn_size_bin(pub->n);
			bn_write_bin(buf, len, a);
			TEST_ASSERT(cp_bdpe_dec(&out, buf, len, prv) == RLC_OK, end);
			TEST_ASSERT(in == out, end);
		} TEST_END;
	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(a);
	bn_free(b);
	bdpe_free(pub);
	bdpe_free(prv);
	return code;
}

static int paillier(void) {
	int code = RLC_ERR;
	bn_t a, b, c, d, s, pub;
	phpe_t prv;
	int result;

	bn_null(a);
	bn_null(b);
	bn_null(c);
	bn_null(d);
	bn_null(s);
	bn_null(pub);
	phpe_null(prv);

	RLC_TRY {
		bn_new(a);
		bn_new(b);
		bn_new(c);
		bn_new(d);
		bn_new(s);
		bn_new(pub);
		phpe_new(prv);

		result = cp_phpe_gen(pub, prv, RLC_BN_BITS / 2);

		TEST_CASE("paillier encryption/decryption is correct") {
			TEST_ASSERT(result == RLC_OK, end);
			bn_rand_mod(a, pub);
			TEST_ASSERT(cp_phpe_enc(c, a, pub) == RLC_OK, end);
			TEST_ASSERT(cp_phpe_dec(b, c, prv) == RLC_OK, end);
			TEST_ASSERT(bn_cmp(a, b) == RLC_EQ, end);
		}
		TEST_END;

		TEST_CASE("paillier encryption/decryption is homomorphic") {
			TEST_ASSERT(result == RLC_OK, end);
			bn_rand_mod(a, pub);
			bn_rand_mod(b, pub);
			TEST_ASSERT(cp_phpe_enc(c, a, pub) == RLC_OK, end);
			TEST_ASSERT(cp_phpe_enc(d, b, pub) == RLC_OK, end);
			TEST_ASSERT(cp_phpe_add(c, c, d, pub) == RLC_OK, end);
			TEST_ASSERT(cp_phpe_dec(d, c, prv) == RLC_OK, end);
			bn_add(a, a, b);
			bn_mod(a, a, pub);
			TEST_ASSERT(bn_cmp(a, d) == RLC_EQ, end);
		}
		TEST_END;

		for (int k = 1; k <= 2; k++) {
			result = cp_ghpe_gen(pub, s, RLC_BN_BITS / (2 * k));
			util_print("(s = %d) ", k);
			TEST_CASE("general paillier encryption/decryption is correct") {
				TEST_ASSERT(result == RLC_OK, end);
				bn_rand(a, RLC_POS, k * (bn_bits(pub) - 1));
				TEST_ASSERT(cp_ghpe_enc(c, a, pub, k) == RLC_OK, end);
				TEST_ASSERT(cp_ghpe_dec(b, c, pub, s, k) == RLC_OK, end);
				TEST_ASSERT(bn_cmp(a, b) == RLC_EQ, end);
			}  TEST_END;

			util_print("(s = %d) ", k);
			TEST_CASE("general paillier encryption/decryption is homomorphic") {
				TEST_ASSERT(result == RLC_OK, end);
				bn_rand(a, RLC_POS, k * (bn_bits(pub) - 1));
				bn_rand(b, RLC_POS, k * (bn_bits(pub) - 1));
				TEST_ASSERT(cp_ghpe_enc(c, a, pub, k) == RLC_OK, end);
				TEST_ASSERT(cp_ghpe_enc(d, b, pub, k) == RLC_OK, end);
				bn_mul(c, c, d);
				bn_sqr(d, pub);
				if (k == 2) {
					bn_mul(d, d, pub);
				}
				bn_mod(c, c, d);
				TEST_ASSERT(cp_ghpe_dec(c, c, pub, s, k) == RLC_OK, end);
				bn_add(a, a, b);
				bn_copy(d, pub);
				if (k == 2) {
					bn_mul(d, d, pub);
				}
				bn_mod(a, a, d);
				TEST_ASSERT(bn_cmp(a, c) == RLC_EQ, end);
			}
			TEST_END;
		}
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(a);
	bn_free(b);
	bn_free(c);
	bn_free(d);
	bn_free(s);
	bn_free(pub);
	phpe_free(prv);
	return code;
}

static int subgroup_paillier() {
	int code = RLC_ERR;
	bn_t a, b, c, d;
	shpe_t pub, prv;
	int result, bits;

	bn_null(a);
	bn_null(b);
	bn_null(c);
	bn_null(d);
	shpe_null(pub);
	shpe_null(prv);

	RLC_TRY {
		bn_new(a);
		bn_new(b);
		bn_new(c);
		bn_new(d);
        shpe_new(pub);
		shpe_new(prv);

		for (bits = 3; bits < 6; bits++) {
			result = cp_shpe_gen(pub, prv, RLC_BN_BITS / (bits * 2), RLC_BN_BITS / 2);

			util_print("(o = %d, |n| = %d) ", RLC_BN_BITS / (bits * 2), RLC_BN_BITS / 2);
			TEST_CASE("subgroup paillier encryption/decryption is correct") {
				TEST_ASSERT(result == RLC_OK, end);
				bn_rand_mod(a, pub->crt->n);
				TEST_ASSERT(cp_shpe_enc(c, a, pub) == RLC_OK, end);
				TEST_ASSERT(cp_shpe_dec(b, c, prv) == RLC_OK, end);
				TEST_ASSERT(bn_cmp(a, b) == RLC_EQ, end);
			}
			TEST_END;

			util_print("(o = %d, |n| = %d) ", RLC_BN_BITS / (bits * 2), RLC_BN_BITS / 2);
			TEST_CASE("subgroup paillier faster encryption with private key is correct") {
				TEST_ASSERT(result == RLC_OK, end);
				bn_rand_mod(a, pub->crt->n);
				TEST_ASSERT(cp_shpe_enc_prv(c, a, prv) == RLC_OK, end);
				TEST_ASSERT(cp_shpe_dec(b, c, prv) == RLC_OK, end);
				TEST_ASSERT(bn_cmp(a, b) == RLC_EQ, end);
			}
			TEST_END;

			util_print("(o = %d, |n| = %d) ", RLC_BN_BITS / (bits * 2), RLC_BN_BITS / 2);
			TEST_CASE("subgroup paillier encryption/decryption is homomorphic") {
				TEST_ASSERT(result == RLC_OK, end);
				bn_rand_mod(a, pub->crt->n);
				bn_rand_mod(b, pub->crt->n);
				TEST_ASSERT(cp_shpe_enc(c, a, pub) == RLC_OK, end);
				TEST_ASSERT(cp_shpe_enc(d, b, pub) == RLC_OK, end);
				bn_mul(c, c, d);
				bn_sqr(d, pub->crt->n);
				bn_mod(c, c, d);
				TEST_ASSERT(cp_shpe_dec(d, c, prv) == RLC_OK, end);
				bn_add(a, a, b);
				bn_mod(a, a, pub->crt->n);
				TEST_ASSERT(bn_cmp(a, d) == RLC_EQ, end);
			}
			TEST_END;
		}
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(a);
	bn_free(b);
	bn_free(c);
	bn_free(d);
	shpe_free(pub);
	shpe_free(prv);
	return code;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the CP module", 0);
	util_banner("Protocols based on integer factorization:\n", 0);

	if (rsa() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (rabin() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (benaloh() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (paillier() != RLC_OK) {
		core_clean();
		return 1;
	}

	if (subgroup_paillier() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
