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
 * Benchmarks for cryptographic protocols based on integer factorization.
 *
 * @version $Id$
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

static void rsa(void) {
	rsa_t pub, prv;
	uint8_t in[10], new[10], h[RLC_MD_LEN], out[RLC_BN_BITS / 8 + 1];
	size_t out_len, new_len;

	rsa_null(pub);
	rsa_null(prv);

	rsa_new(pub);
	rsa_new(prv);

	BENCH_ONE("cp_rsa_gen", cp_rsa_gen(pub, prv, RLC_BN_BITS), 1);

	BENCH_RUN("cp_rsa_enc") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_enc(out, &out_len, in, sizeof(in), pub));
		cp_rsa_dec(new, &new_len, out, out_len, prv);
	} BENCH_END;

	BENCH_RUN("cp_rsa_dec") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
		BENCH_ADD(cp_rsa_dec(new, &new_len, out, out_len, prv));
	} BENCH_END;

	BENCH_RUN("cp_rsa_sig (h = 0)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv));
	} BENCH_END;

	BENCH_RUN("cp_rsa_sig (h = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		BENCH_ADD(cp_rsa_sig(out, &out_len, h, RLC_MD_LEN, 1, prv));
	} BENCH_END;

	BENCH_RUN("cp_rsa_ver (h = 0)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv);
		BENCH_ADD(cp_rsa_ver(out, out_len, in, sizeof(in), 0, pub));
	} BENCH_END;

	BENCH_RUN("cp_rsa_ver (h = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		cp_rsa_sig(out, &out_len, h, RLC_MD_LEN, 1, prv);
		BENCH_ADD(cp_rsa_ver(out, out_len, h, RLC_MD_LEN, 1, pub));
	} BENCH_END;

	BENCH_RUN("cp_rsa_enc (pkcs1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_enc(out, &out_len, in, sizeof(in), pub, pkcs1));
		cp_rsa_dec(new, &new_len, out, out_len, prv, pkcs1);
	} BENCH_END;

	BENCH_RUN("cp_rsa_dec (pkcs1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_enc(out, &out_len, in, sizeof(in), pub, pkcs1);
		BENCH_ADD(cp_rsa_dec(new, &new_len, out, out_len, prv, pkcs1));
	} BENCH_END;

	BENCH_RUN("cp_rsa_sig (pkcs1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv, pkcs1));
	} BENCH_END;

	BENCH_RUN("cp_rsa_ver (pkcs1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(in, sizeof(in));
		cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv, pkcs1);
		BENCH_ADD(cp_rsa_ver(out, out_len, in, sizeof(in), 0, pub, pkcs1));
	} BENCH_END;

	rsa_free(pub);
	rsa_free(prv);
}

static void trsa(void) {
	rsa_t ek, dk;
	uint8_t in[10], new[10], lab[4] = { 1, 2, 3, 4 };
	uint8_t out[RLC_BN_BITS / 8 + 1];
	size_t out_len, new_len;
	bn_t e;

	bn_null(e);
	rsa_null(ek);
	rsa_null(dk);

	bn_new(e);
	rsa_new(ek);
	rsa_new(dk);

	/* Costs grow linearly with tau and theta, so measure few steps. A single
	 * step of encryption uses a ladder, as the key is then secret. */
	BENCH_ONE("cp_trsa_gen", cp_trsa_gen(ek, dk, RLC_BN_BITS, 1, 1), 1);

	BENCH_RUN("cp_trsa_enc (tau = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_trsa_enc(out, &out_len, in, sizeof(in), lab,
				sizeof(lab), ek, 1));
	} BENCH_END;

	BENCH_RUN("cp_trsa_enc (tau = 2)") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_trsa_enc(out, &out_len, in, sizeof(in), lab,
				sizeof(lab), ek, 2));
	} BENCH_END;

	BENCH_RUN("cp_trsa_dec (theta = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = sizeof(new);
		rand_bytes(in, sizeof(in));
		cp_trsa_enc(out, &out_len, in, sizeof(in), lab, sizeof(lab), ek, 1);
		BENCH_ADD(cp_trsa_dec(new, &new_len, out, out_len, lab,
				sizeof(lab), dk, 1));
	} BENCH_END;

	BENCH_RUN("cp_trsa_enc (oaepp, tau = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_trsa_enc(out, &out_len, in, sizeof(in), lab,
				sizeof(lab), ek, 1, oaepp));
	} BENCH_END;

	BENCH_RUN("cp_trsa_dec (oaepp, theta = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = sizeof(new);
		rand_bytes(in, sizeof(in));
		cp_trsa_enc(out, &out_len, in, sizeof(in), lab, sizeof(lab), ek, 1,
				oaepp);
		BENCH_ADD(cp_trsa_dec(new, &new_len, out, out_len, lab,
				sizeof(lab), dk, 1, oaepp));
	} BENCH_END;

	/* Moduli from Cunningham chains are slow to find, so time a single one. */
	bn_set_2b(e, 16);
	bn_add_dig(e, e, 1);
	BENCH_ONE("cp_trsa_gen_exp", cp_trsa_gen_exp(ek, dk, RLC_BN_BITS, e, 1,
			1), 1);

	bn_free(e);
	rsa_free(ek);
	rsa_free(dk);
}

static void rabin(void) {
	rabin_t pub, prv;
	uint8_t in[1000], new[1000], out[RLC_BN_BITS / 8 + 1];
	size_t in_len, out_len, new_len;

	rabin_null(pub);
	rabin_null(prv);

	rabin_new(pub);
	rabin_new(prv);

	BENCH_ONE("cp_rabin_gen", cp_rabin_gen(pub, prv, RLC_BN_BITS), 1);

	BENCH_RUN("cp_rabin_enc") {
		in_len = bn_size_bin(pub->n) - 10;
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(in, in_len);
		BENCH_ADD(cp_rabin_enc(out, &out_len, in, in_len, pub));
		cp_rabin_dec(new, &new_len, out, out_len, prv);
	} BENCH_END;

	BENCH_RUN("cp_rabin_dec") {
		in_len = bn_size_bin(pub->n) - 10;
		new_len = in_len;
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(in, in_len);
		cp_rabin_enc(out, &out_len, in, in_len, pub);
		BENCH_ADD(cp_rabin_dec(new, &new_len, out, out_len, prv));
	} BENCH_END;

	rabin_free(pub);
	rabin_free(prv);
}

static void benaloh(void) {
	bdpe_t pub, prv;
	dig_t in, new;
	uint8_t out[RLC_BN_BITS / 8 + 1];
	size_t out_len;
	dig_t prime = 0xFB;

	bdpe_null(pub);
	bdpe_null(prv);

	bdpe_new(pub);
	bdpe_new(prv);

	BENCH_ONE("cp_bdpe_gen", cp_bdpe_gen(pub, prv, prime, RLC_BN_BITS), 1);

	BENCH_RUN("cp_bdpe_enc") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(out, 1);
		in = out[0] % prime;
		BENCH_ADD(cp_bdpe_enc(out, &out_len, in, pub));
		cp_bdpe_dec(&new, out, out_len, prv);
	} BENCH_END;

	BENCH_RUN("cp_bdpe_dec") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(out, 1);
		in = out[0] % prime;
		cp_bdpe_enc(out, &out_len, in, pub);
		BENCH_ADD(cp_bdpe_dec(&new, out, out_len, prv));
	} BENCH_END;

	bdpe_free(pub);
	bdpe_free(prv);
}

static void paillier(void) {
	bn_t c, m, pub;
	phpe_t prv;
    shpe_t spub, sprv;

	bn_null(c);
	bn_null(m);
	bn_null(pub);
	phpe_null(prv);
    shpe_null(spub);
    shpe_null(sprv);

	bn_new(c);
	bn_new(m);
	bn_new(pub);
	phpe_new(prv);
    shpe_new(spub);
    shpe_new(sprv);

	BENCH_ONE("cp_phpe_gen", cp_phpe_gen(pub, prv, RLC_BN_BITS / 2), 1);

	BENCH_RUN("cp_phpe_enc") {
		bn_rand_mod(m, pub);
		BENCH_ADD(cp_phpe_enc(c, m, pub));
	} BENCH_END;

	BENCH_RUN("cp_phpe_add") {
		bn_rand_mod(m, pub);
		cp_phpe_enc(c, m, pub);
		BENCH_ADD(cp_phpe_add(c, c, c, pub));
	} BENCH_END;

	BENCH_RUN("cp_phpe_dec") {
		bn_rand_mod(m, pub);
		cp_phpe_enc(c, m, pub);
		BENCH_ADD(cp_phpe_dec(m, c, prv));
	} BENCH_END;

	BENCH_ONE("cp_shpe_gen", cp_shpe_gen(spub, sprv, RLC_BN_BITS / 10, RLC_BN_BITS / 2), 1);

	BENCH_RUN("cp_shpe_enc") {
		bn_rand_mod(m, spub->crt->n);
		BENCH_ADD(cp_shpe_enc(c, m, spub));
	} BENCH_END;

	BENCH_RUN("cp_shpe_enc_prv") {
		bn_rand_mod(m, spub->crt->n);
		BENCH_ADD(cp_shpe_enc_prv(c, m, sprv));
	} BENCH_END;

	BENCH_RUN("cp_shpe_dec (1)") {
		bn_rand_mod(m, spub->crt->n);
		cp_shpe_enc(c, m, spub);
		BENCH_ADD(cp_shpe_dec(m, c, sprv));
	} BENCH_END;

	BENCH_RUN("cp_shpe_dec (2)") {
		bn_rand_mod(m, spub->crt->n);
		cp_shpe_enc_prv(c, m, sprv);
		BENCH_ADD(cp_shpe_dec(m, c, sprv));
	} BENCH_END;

	BENCH_ONE("cp_ghpe_gen", cp_ghpe_gen(pub, prv->n, RLC_BN_BITS / 2), 1);

	BENCH_RUN("cp_ghpe_enc (1)") {
		bn_rand_mod(m, pub);
		BENCH_ADD(cp_ghpe_enc(c, m, pub, 1));
	} BENCH_END;

	BENCH_RUN("cp_ghpe_dec (1)") {
		bn_rand_mod(m, pub);
		cp_ghpe_enc(m, c, pub, 1);
		BENCH_ADD(cp_ghpe_dec(c, m, pub, prv->n, 1));
	} BENCH_END;

	BENCH_ONE("cp_ghpe_gen", cp_ghpe_gen(pub, prv->n, RLC_BN_BITS / 4), 1);

	BENCH_RUN("cp_ghpe_enc (2)") {
		bn_rand(m, RLC_POS, 2 * bn_bits(pub) - 1);
		BENCH_ADD(cp_ghpe_enc(m, c, pub, 2));
	} BENCH_END;

	BENCH_RUN("cp_ghpe_dec (2)") {
		bn_rand(m, RLC_POS, 2 * bn_bits(pub) - 1);
		cp_ghpe_enc(m, c, pub, 2);
		BENCH_ADD(cp_ghpe_dec(c, m, pub, prv->n, 2));
	} BENCH_END;

	bn_free(c);
	bn_free(m);
	bn_free(pub);
	phpe_free(prv);
    shpe_free(spub);
    shpe_free(sprv);
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the CP module:", 0);

	util_banner("Protocols based on integer factorization:\n", 0);
	rsa();
	trsa();
	rabin();
	paillier();
	benaloh();

	core_clean();
	return 0;
}
