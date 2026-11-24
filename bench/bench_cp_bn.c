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
		cp_ghpe_enc(c, m, pub, 1);
		BENCH_ADD(cp_ghpe_dec(m, c, pub, prv->n, 1));
	} BENCH_END;

	BENCH_ONE("cp_ghpe_gen", cp_ghpe_gen(pub, prv->n, RLC_BN_BITS / 4), 1);

	BENCH_RUN("cp_ghpe_enc (2)") {
		bn_rand(m, RLC_POS, 2 * bn_bits(pub) - 1);
		BENCH_ADD(cp_ghpe_enc(c, m, pub, 2));
	} BENCH_END;

	BENCH_RUN("cp_ghpe_dec (2)") {
		bn_rand(m, RLC_POS, 2 * bn_bits(pub) - 1);
		cp_ghpe_enc(c, m, pub, 2);
		BENCH_ADD(cp_ghpe_dec(m, c, pub, prv->n, 2));
	} BENCH_END;

	bn_free(c);
	bn_free(m);
	bn_free(pub);
	phpe_free(prv);
    shpe_free(spub);
    shpe_free(sprv);
}

/**
 * Upper bound on the timestamp space used in the benchmarks.
 */
#define BENCH_TDS_BOUND	1024

/**
 * Timestamp used in the benchmarks, in the middle of the timestamp space.
 */
#define BENCH_TDS_STAMP	512

/**
 * Benchmarks key generation, signing, verification and serialization. These
 * are independent of the delay parameter.
 */
static void tds_short(size_t bits) {
	tds_t pub, prv;
	tds_sig_t sig;
	uint8_t m[10], bin[4 * (RLC_BN_BITS / 8) + RLC_TDS_SALT];
	size_t len;

	tds_null(pub);
	tds_null(prv);
	tds_sig_null(sig);

	tds_new(pub);
	tds_new(prv);
	tds_sig_new(sig);

	rand_bytes(m, sizeof(m));

	BENCH_ONE("cp_tds_gen", cp_tds_gen(pub, prv, bits, 1 << 10,
			BENCH_TDS_BOUND), 1);

	BENCH_RUN("cp_tds_sign") {
		BENCH_ADD(cp_tds_sign(sig, NULL, m, sizeof(m), BENCH_TDS_STAMP, prv));
	} BENCH_END;

	BENCH_RUN("cp_tds_ver") {
		cp_tds_sign(sig, NULL, m, sizeof(m), BENCH_TDS_STAMP, prv);
		BENCH_ADD(cp_tds_ver(sig, m, sizeof(m), BENCH_TDS_STAMP, pub));
	} BENCH_END;

	BENCH_RUN("cp_tds_write_sig") {
		len = sizeof(bin);
		BENCH_ADD(cp_tds_write_sig(bin, &len, sig, pub));
	} BENCH_END;

	len = sizeof(bin);
	cp_tds_write_sig(bin, &len, sig, pub);
	util_print("BENCH: signature size%*c = %d bytes\n", 32 - 14, ' ',
			(int)len);

	tds_free(pub);
	tds_free(prv);
	tds_sig_free(sig);
}

/**
 * Benchmarks the public sequential evaluation for a given delay parameter.
 */
static void tds_delay(size_t bits, size_t delay) {
	tds_t pub, prv;
	tds_sig_t sig, alt;
	uint8_t m[10], n[10];

	tds_null(pub);
	tds_null(prv);
	tds_sig_null(sig);
	tds_sig_null(alt);

	tds_new(pub);
	tds_new(prv);
	tds_sig_new(sig);
	tds_sig_new(alt);

	rand_bytes(m, sizeof(m));
	rand_bytes(n, sizeof(n));

	cp_tds_gen(pub, prv, bits, delay, BENCH_TDS_BOUND);
	cp_tds_sign(sig, NULL, m, sizeof(m), BENCH_TDS_STAMP, prv);

	BENCH_ONE("cp_tds_alt", cp_tds_alt(alt, NULL, n, sizeof(n),
			BENCH_TDS_STAMP - 1, sig, m, sizeof(m), BENCH_TDS_STAMP, pub), 1);

	tds_free(pub);
	tds_free(prv);
	tds_sig_free(sig);
	tds_sig_free(alt);
}


#if defined(WITH_QF)

/** Size in bits of the plaintext prime used by the CL benchmarks. */
#define BENCH_CLHE_PLAIN	64
/** Size in bits of the fundamental discriminant used by the CL benchmarks. */
#define BENCH_CLHE_DISC		512

/**
 * Benchmarks one variant of the CL system. Setting up and generating a key are
 * measured separately, since both build precomputation tables and neither is on
 * the path of an encryption.
 */
static void clhe(int compact) {
	clhe_t c;
	clhe_pk_t pk;
	bn_t q, sk, m, n, s, r, bound;
	qf_t c1, c2, d1, d2, e1, e2;

	clhe_null(c);
	clhe_pk_null(pk);
	bn_null(q);
	bn_null(sk);
	bn_null(m);
	bn_null(n);
	bn_null(s);
	bn_null(r);
	bn_null(bound);
	qf_null(c1);
	qf_null(c2);
	qf_null(d1);
	qf_null(d2);
	qf_null(e1);
	qf_null(e2);

	clhe_new(c);
	clhe_pk_new(pk);
	bn_new(q);
	bn_new(sk);
	bn_new(m);
	bn_new(n);
	bn_new(s);
	bn_new(r);
	bn_new(bound);
	qf_new(c1);
	qf_new(c2);
	qf_new(d1);
	qf_new(d2);
	qf_new(e1);
	qf_new(e2);

	bn_gen_prime(q, BENCH_CLHE_PLAIN);
	cp_clhe_set(c, q, BENCH_CLHE_DISC, compact);
	cp_clhe_gen(pk, sk, c);
	qf_class(bound, &(core_get()->qf_dk));
	bn_lsh(bound, bound, 40);

	if (compact) {
		BENCH_ONE("cp_clhe_set (compact)", cp_clhe_set(c, q, BENCH_CLHE_DISC,
				compact), 1);
	} else {
		BENCH_ONE("cp_clhe_set (plain)", cp_clhe_set(c, q, BENCH_CLHE_DISC,
				compact), 1);
	}

	/* the parameters were replaced by the loop above, so rebuild the key */
	cp_clhe_set(c, q, BENCH_CLHE_DISC, compact);
	cp_clhe_gen(pk, sk, c);
	qf_class(bound, &(core_get()->qf_dk));
	bn_lsh(bound, bound, 40);

	BENCH_RUN("cp_clhe_gen") {
		BENCH_ADD(cp_clhe_gen(pk, sk, c));
	} BENCH_END;

	cp_clhe_gen(pk, sk, c);

	BENCH_RUN("cp_clhe_enc") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		BENCH_ADD(cp_clhe_enc(c1, c2, c, pk, m, r));
	} BENCH_END;

	BENCH_RUN("cp_clhe_dec") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		BENCH_ADD(cp_clhe_dec(n, c, sk, c1, c2));
	} BENCH_END;

	BENCH_RUN("cp_clhe_dec (zero message)") {
		/* the discrete logarithm exits immediately on the identity, so this
		 * bounds the part of decryption that is not the exponentiation */
		bn_zero(m);
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		BENCH_ADD(cp_clhe_dec(n, c, sk, c1, c2));
	} BENCH_END;

	BENCH_RUN("cp_clhe_add") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		bn_rand_mod(n, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(d1, d2, c, pk, n, r);
		bn_rand_mod(r, bound);
		BENCH_ADD(cp_clhe_add(e1, e2, c, pk, c1, c2, d1, d2, r));
	} BENCH_END;

	BENCH_RUN("cp_clhe_mul") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		bn_rand_mod(s, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		BENCH_ADD(cp_clhe_mul(e1, e2, c, pk, c1, c2, s, r));
	} BENCH_END;

	BENCH_RUN("cp_clhe_mul (small scalar)") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		bn_set_dig(s, 3);
		bn_rand_mod(r, bound);
		BENCH_ADD(cp_clhe_mul(e1, e2, c, pk, c1, c2, s, r));
	} BENCH_END;

	clhe_free(c);
	clhe_pk_free(pk);
	bn_free(q);
	bn_free(sk);
	bn_free(m);
	bn_free(n);
	bn_free(s);
	bn_free(r);
	bn_free(bound);
	qf_free(c1);
	qf_free(c2);
	qf_free(d1);
	qf_free(d2);
	qf_free(e1);
	qf_free(e2);
}

/**
 * Samples a modulus admitting the class group setting: three modulo four, so
 * that its negation is a fundamental discriminant, and each factor inert in
 * the other.
 */
static void clhe_modulus(rsa_t pub, rsa_t prv, size_t bits) {
	dig_t r;

	do {
		cp_rsa_gen(pub, prv, bits);
		bn_mod_dig(&r, pub->crt->n, 4);
	} while (r != 3 || bn_smb_leg(prv->crt->p, prv->crt->q) != -1);
}

/** Size in bits of the composite conductor used by the timed CL benchmarks. */
#define BENCH_TCLHE_MOD		512
/** Delay used by the timed CL benchmarks, as a number of squarings. */
#define BENCH_TCLHE_DELAY	64

/**
 * Benchmarks the timed variant over a composite conductor. Key generation is
 * measured on its own, since it walks the delay once and builds the
 * precomputation tables, and decryption is measured at several delays so that
 * the fixed cost separates from the marginal cost of a squaring.
 */
static void clthe(int compact) {
	clhe_t c;
	clhe_pk_t pk;
	rsa_t pub, prv;
	bn_t m, n, r, bound;
	qf_t c1, c2;

	clhe_null(c);
	clhe_pk_null(pk);
	rsa_null(pub);
	rsa_null(prv);
	bn_null(m);
	bn_null(n);
	bn_null(r);
	bn_null(bound);
	qf_null(c1);
	qf_null(c2);

	clhe_new(c);
	clhe_pk_new(pk);
	rsa_new(pub);
	rsa_new(prv);
	bn_new(m);
	bn_new(n);
	bn_new(r);
	bn_new(bound);
	qf_new(c1);
	qf_new(c2);

	clhe_modulus(pub, prv, BENCH_TCLHE_MOD);
	cp_clhe_set(c, pub->crt->n, 0, compact);
	cp_clhe_bnd(bound);

	if (compact) {
		BENCH_ONE("cp_clthe_gen (compact)",
				cp_clthe_gen(pk, c, BENCH_TCLHE_DELAY), 1);
	} else {
		BENCH_ONE("cp_clthe_gen (plain)",
				cp_clthe_gen(pk, c, BENCH_TCLHE_DELAY), 1);
	}
	BENCH_ONE("cp_clthe_gen (4x delay)",
			cp_clthe_gen(pk, c, 4 * BENCH_TCLHE_DELAY), 1);

	cp_clthe_gen(pk, c, BENCH_TCLHE_DELAY);

	BENCH_RUN("cp_clhe_enc (timed key)") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		BENCH_ADD(cp_clhe_enc(c1, c2, c, pk, m, r));
	} BENCH_END;

	BENCH_RUN("cp_clthe_dec") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		BENCH_ADD(cp_clthe_dec(n, c, c1, c2, BENCH_TCLHE_DELAY));
	} BENCH_END;

	BENCH_RUN("cp_clthe_dec (zero message)") {
		bn_zero(m);
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		BENCH_ADD(cp_clthe_dec(n, c, c1, c2, BENCH_TCLHE_DELAY));
	} BENCH_END;

	/* a ciphertext made for one delay cannot be opened at another, so the
	* key is regenerated to isolate the marginal cost of the delay */
	cp_clthe_gen(pk, c, 2 * BENCH_TCLHE_DELAY);
	BENCH_RUN("cp_clthe_dec (2x delay)") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		BENCH_ADD(cp_clthe_dec(n, c, c1, c2, 2 * BENCH_TCLHE_DELAY));
	} BENCH_END;

	cp_clthe_gen(pk, c, 4 * BENCH_TCLHE_DELAY);
	BENCH_RUN("cp_clthe_dec (4x delay)") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		BENCH_ADD(cp_clthe_dec(n, c, c1, c2, 4 * BENCH_TCLHE_DELAY));
	} BENCH_END;

	/* a delay spanning the crossover between the two variants: the compact
	* one saves on every squaring but pays a lift once, so it only comes out
	* ahead once the delay is long enough to amortise it */
	cp_clthe_gen(pk, c, 64 * BENCH_TCLHE_DELAY);
	BENCH_RUN("cp_clthe_dec (64x delay)") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		BENCH_ADD(cp_clthe_dec(n, c, c1, c2, 64 * BENCH_TCLHE_DELAY));
	} BENCH_END;

	cp_clthe_gen(pk, c, BENCH_TCLHE_DELAY);
	BENCH_RUN("cp_clthe_dec (rejecting)") {
		bn_rand_mod(m, &(core_get()->qf_q));
		bn_rand_mod(r, bound);
		cp_clhe_enc(c1, c2, c, pk, m, r);
		/* squaring the second component moves it out of the coset, so the
		* kernel check refuses it after the delay is already paid */
		qf_dup(c2, c2, &(core_get()->qf_d));
		BENCH_ADD(cp_clthe_dec(n, c, c1, c2, BENCH_TCLHE_DELAY));
	} BENCH_END;

	clhe_free(c);
	clhe_pk_free(pk);
	rsa_free(pub);
	rsa_free(prv);
	bn_free(m);
	bn_free(n);
	bn_free(r);
	bn_free(bound);
	qf_free(c1);
	qf_free(c2);
}

/** Size in bits of the composite conductor used by the CL-RSA benchmarks. */
#define BENCH_CLRSA_MOD		512
/** Delay used by the CL-RSA benchmarks, as a number of squarings. */
#define BENCH_CLRSA_DELAY	64
/** Public exponent the CL-RSA benchmarks prove a root for. */
#define BENCH_CLRSA_EXP		3

/**
 * Benchmarks the CL-RSA argument. The two phases of the prover are measured
 * apart, since only the commit phase samples masks and only it can be run
 * before the statement is known.
 */
static void clrsa(void) {
	clhe_t c;
	clhe_pk_t pk;
	rsa_t pub, prv;
	bn_t d, e, phi, x, y, rho, t, eta, xi, bound, chl;
	bn_t rsp[RLC_CLRSA_RSP], aux[RLC_CLRSA_AUX];
	qf_t hh, c1, c2;
	qf_t cmt[RLC_CLRSA_CMT];
	size_t len;

	clhe_null(c);
	clhe_pk_null(pk);
	rsa_null(pub);
	rsa_null(prv);
	bn_null(d);
	bn_null(e);
	bn_null(phi);
	bn_null(x);
	bn_null(y);
	bn_null(rho);
	bn_null(t);
	bn_null(eta);
	bn_null(xi);
	bn_null(bound);
	bn_null(chl);
	qf_null(hh);
	qf_null(c1);
	qf_null(c2);
	for (int j = 0; j < RLC_CLRSA_RSP; j++) {
		bn_null(rsp[j]);
	}
	for (int j = 0; j < RLC_CLRSA_AUX; j++) {
		bn_null(aux[j]);
	}
	for (int j = 0; j < RLC_CLRSA_CMT; j++) {
		qf_null(cmt[j]);
	}

	clhe_new(c);
	clhe_pk_new(pk);
	rsa_new(pub);
	rsa_new(prv);
	bn_new(d);
	bn_new(e);
	bn_new(phi);
	bn_new(x);
	bn_new(y);
	bn_new(rho);
	bn_new(t);
	bn_new(eta);
	bn_new(xi);
	bn_new(bound);
	bn_new(chl);
	qf_new(hh);
	qf_new(c1);
	qf_new(c2);
	/* bn_new and qf_new are multi-statement macros without a do-while
	* wrapper, so they need braces as a loop body */
	for (int j = 0; j < RLC_CLRSA_RSP; j++) {
		bn_new(rsp[j]);
	}
	for (int j = 0; j < RLC_CLRSA_AUX; j++) {
		bn_new(aux[j]);
	}
	for (int j = 0; j < RLC_CLRSA_CMT; j++) {
		qf_new(cmt[j]);
	}

	bn_set_dig(e, BENCH_CLRSA_EXP);
	do {
		clhe_modulus(pub, prv, BENCH_CLRSA_MOD);
		bn_sub_dig(phi, prv->crt->p, 1);
		bn_sub_dig(t, prv->crt->q, 1);
		bn_mul(phi, phi, t);
		bn_gcd(t, e, phi);
	} while (bn_cmp_dig(t, 1) != RLC_EQ);
	bn_mod_inv(d, e, phi);

	cp_clhe_set(c, pub->crt->n, 0, 1);
	cp_clhe_bnd(bound);
	cp_clthe_gen(pk, c, BENCH_CLRSA_DELAY);
	bn_set_dig(chl, 1);
	bn_lsh(chl, chl, RLC_CLRSA_CHL);

	BENCH_ONE("cp_clrsa_set", cp_clrsa_set(hh, c, pk), 1);
	cp_clrsa_set(hh, c, pk);

	do {
		bn_rand_mod(x, pub->crt->n);
		bn_gcd(t, x, pub->crt->n);
	} while (bn_cmp_dig(t, 1) != RLC_EQ || bn_is_zero(x));
	bn_mxp(y, x, d, pub->crt->n);
	bn_rand_mod(rho, bound);
	cp_clhe_enc(c1, c2, c, pk, y, rho);

	BENCH_RUN("cp_clrsa_cmt") {
		BENCH_ADD(cp_clrsa_cmt(cmt, aux, c, y, c2, hh));
	} BENCH_END;

	cp_clrsa_cmt(cmt, aux, c, y, c2, hh);

	BENCH_RUN("cp_clrsa_rsp") {
		bn_rand_mod(eta, chl);
		bn_rand_mod(xi, chl);
		BENCH_ADD(cp_clrsa_rsp(rsp, aux, eta, xi, y, rho));
	} BENCH_END;

	bn_rand_mod(eta, chl);
	bn_rand_mod(xi, chl);
	cp_clrsa_rsp(rsp, aux, eta, xi, y, rho);

	BENCH_RUN("cp_clrsa_chk") {
		BENCH_ADD(cp_clrsa_chk(cmt, rsp, eta, xi, c, x, c1, c2, hh));
	} BENCH_END;

	BENCH_RUN("cp_clrsa_sig") {
		BENCH_ADD(cp_clrsa_sig(cmt, rsp, c, y, rho, c1, c2, x, hh));
	} BENCH_END;

	cp_clrsa_sig(cmt, rsp, c, y, rho, c1, c2, x, hh);

	BENCH_RUN("cp_clrsa_ver") {
		BENCH_ADD(cp_clrsa_ver(cmt, rsp, c, x, c1, c2, hh));
	} BENCH_END;

	BENCH_RUN("cp_clrsa_ver (rejecting)") {
		bn_add_dig(rsp[0], rsp[0], 1);
		BENCH_ADD(cp_clrsa_ver(cmt, rsp, c, x, c1, c2, hh));
		bn_sub_dig(rsp[0], rsp[0], 1);
	} BENCH_END;

	/* the proof is seven forms and eight integers, so its size is worth
	* reporting alongside the timings */
	cp_clrsa_sig(cmt, rsp, c, y, rho, c1, c2, x, hh);
	len = 0;
	for (int j = 0; j < RLC_CLRSA_CMT; j++) {
		len += bn_size_bin(cmt[j]->a) + bn_size_bin(cmt[j]->b);
	}
	for (int j = 0; j < RLC_CLRSA_RSP; j++) {
		len += bn_size_bin(rsp[j]);
	}
	util_print("BENCH: cp_clrsa proof size%*c = %zu bytes\n",
			(int)(32 - strlen("cp_clrsa proof size")), ' ', len);

	clhe_free(c);
	clhe_pk_free(pk);
	rsa_free(pub);
	rsa_free(prv);
	bn_free(d);
	bn_free(e);
	bn_free(phi);
	bn_free(x);
	bn_free(y);
	bn_free(rho);
	bn_free(t);
	bn_free(eta);
	bn_free(xi);
	bn_free(bound);
	bn_free(chl);
	qf_free(hh);
	qf_free(c1);
	qf_free(c2);
	for (int j = 0; j < RLC_CLRSA_RSP; j++) {
		bn_free(rsp[j]);
	}
	for (int j = 0; j < RLC_CLRSA_AUX; j++) {
		bn_free(aux[j]);
	}
	for (int j = 0; j < RLC_CLRSA_CMT; j++) {
		qf_free(cmt[j]);
	}
}

/** Size in bits of the prime defining the encoded value space. */
#define BENCH_VDF_SPACE		64
/** Size in bits of the fundamental discriminant. */
#define BENCH_VDF_DISC		512
/** Base delay for the benchmarks, as a number of squarings. */
#define BENCH_VDF_DELAY		1024

static void clvdf(void) {
	qf_t f;
	bn_t q, x, y;
	qf_t u1, z1, y1;

	qf_null(f);
	bn_null(q);
	bn_null(x);
	bn_null(y);
	qf_null(u1);
	qf_null(z1);
	qf_null(y1);

	qf_new(f);
	bn_new(q);
	bn_new(x);
	bn_new(y);
	qf_new(u1);
	qf_new(z1);
	qf_new(y1);

	/*
	 * Sampling a discriminant does not succeed for every prime, so a caller
	 * retries rather than treating the first refusal as fatal.
	 */
	do {
		bn_gen_prime(q, BENCH_VDF_SPACE);
	} while (cp_clvdf_set(f, q, BENCH_VDF_DISC) != RLC_OK);

	/*
	 * Setting up samples a discriminant, so each repetition pays for prime
	 * generation rather than for group arithmetic.
	 */
	BENCH_ONE("cp_clvdf_set", cp_clvdf_set(f, q, BENCH_VDF_DISC), 1);

	BENCH_RUN("cp_clvdf_evl (1024)") {
		bn_rand_mod(x, &(core_get()->qf_q));
		BENCH_ADD(cp_clvdf_evl(u1, z1, y1, f, BENCH_VDF_DELAY, x));
	} BENCH_END;

	BENCH_RUN("cp_clvdf_evl (2048)") {
		bn_rand_mod(x, &(core_get()->qf_q));
		BENCH_ADD(cp_clvdf_evl(u1, z1, y1, f, 2 * BENCH_VDF_DELAY, x));
	} BENCH_END;

	BENCH_RUN("cp_clvdf_evl (4096)") {
		bn_rand_mod(x, &(core_get()->qf_q));
		BENCH_ADD(cp_clvdf_evl(u1, z1, y1, f, 4 * BENCH_VDF_DELAY, x));
	} BENCH_END;

	BENCH_RUN("cp_clvdf_dec") {
		bn_rand_mod(x, &(core_get()->qf_q));
		cp_clvdf_evl(u1, z1, y1, f, BENCH_VDF_DELAY, x);
		BENCH_ADD(cp_clvdf_dec(y, BENCH_VDF_DELAY, u1, z1, y1));
	} BENCH_END;

	BENCH_RUN("cp_clvdf_dec_opt") {
		bn_rand_mod(x, &(core_get()->qf_q));
		cp_clvdf_evl(u1, z1, y1, f, BENCH_VDF_DELAY, x);
		BENCH_ADD(cp_clvdf_dec_opt(y, BENCH_VDF_DELAY, u1, z1, y1));
	} BENCH_END;

	BENCH_RUN("cp_clvdf_ver") {
		bn_rand_mod(x, &(core_get()->qf_q));
		cp_clvdf_evl(u1, z1, y1, f, BENCH_VDF_DELAY, x);
		BENCH_ADD(cp_clvdf_ver(BENCH_VDF_DELAY, x, u1, z1, y1));
	} BENCH_END;

	BENCH_RUN("cp_clvdf_dec (rejecting)") {
		/* a triple that fails the kernel test exits before the logarithm */
		bn_rand_mod(x, &(core_get()->qf_q));
		cp_clvdf_evl(u1, z1, y1, f, BENCH_VDF_DELAY, x);
		qf_dup(z1, z1, &(core_get()->qf_b));
		BENCH_ADD(cp_clvdf_dec(y, BENCH_VDF_DELAY, u1, z1, y1));
	} BENCH_END;

	qf_free(f);
	bn_free(q);
	bn_free(x);
	bn_free(y);
	qf_free(u1);
	qf_free(z1);
	qf_free(y1);
}

#endif

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the CP module:", 0);

	util_banner("Protocols based on integer factorization:\n", 0);
	rsa();
	rabin();
	paillier();
	benaloh();
	tds_short(RLC_BN_BITS);
	tds_delay(RLC_BN_BITS, 1 << 10);
	tds_delay(RLC_BN_BITS, 1 << 14);
	tds_delay(RLC_BN_BITS, 1 << 18);

#if defined(WITH_QF)
	util_banner("Protocols based on class groups:\n", 0);
	clhe(0);
	clhe(1);
	clthe(0);
	clthe(1);
	clrsa();
	clvdf();
#endif

	core_clean();
	return 0;
}
