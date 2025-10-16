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
 * Benchmarks for cryptographic protocols.
 *
 * @version $Id$
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

#if defined(WITH_BN)

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

#endif

#if defined(WITH_EC)

static void ecdh(void) {
	bn_t d;
	ec_t p;
	uint8_t key[RLC_MD_LEN];

	bn_null(d);
	ec_null(p);

	bn_new(d);
	ec_new(p);

	BENCH_RUN("cp_ecdh_gen") {
		BENCH_ADD(cp_ecdh_gen(d, p));
	}
	BENCH_END;

	BENCH_RUN("cp_ecdh_key") {
		BENCH_ADD(cp_ecdh_key(key, RLC_MD_LEN, d, p));
	}
	BENCH_END;

	bn_free(d);
	ec_free(p);
}

static void ecmqv(void) {
	bn_t d1, d2;
	ec_t p1, p2;
	uint8_t key[RLC_MD_LEN];

	bn_null(d1);
	bn_null(d2);
	ec_null(p1);
	ec_null(p2);

	bn_new(d1);
	bn_new(d2);
	ec_new(p1);
	ec_new(p2);

	BENCH_RUN("cp_ecmqv_gen") {
		BENCH_ADD(cp_ecmqv_gen(d1, p1));
	}
	BENCH_END;

	cp_ecmqv_gen(d2, p2);

	BENCH_RUN("cp_ecmqv_key") {
		BENCH_ADD(cp_ecmqv_key(key, RLC_MD_LEN, d1, d2, p1, p1, p2));
	}
	BENCH_END;

	bn_free(d1);
	bn_free(d2);
	ec_free(p1);
	ec_free(p2);
}

static void ecies(void) {
	ec_t q, r;
	bn_t d;
	uint8_t in[10], out[16 + RLC_MD_LEN];
	size_t in_len, out_len;

	bn_null(d);
	ec_null(q);
	ec_null(r);

	ec_new(q);
	ec_new(r);
	bn_new(d);

	BENCH_RUN("cp_ecies_gen") {
		BENCH_ADD(cp_ecies_gen(d, q));
	}
	BENCH_END;

	BENCH_RUN("cp_ecies_enc") {
		in_len = sizeof(in);
		out_len = sizeof(out);
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_ecies_enc(r, out, &out_len, in, in_len, q));
		cp_ecies_dec(out, &out_len, r, out, out_len, d);
	}
	BENCH_END;

	BENCH_RUN("cp_ecies_dec") {
		in_len = sizeof(in);
		out_len = sizeof(out);
		rand_bytes(in, sizeof(in));
		cp_ecies_enc(r, out, &out_len, in, in_len, q);
		BENCH_ADD(cp_ecies_dec(in, &in_len, r, out, out_len, d));
	}
	BENCH_END;

	ec_free(q);
	ec_free(r);
	bn_free(d);
}

static void ecdsa(void) {
	uint8_t msg[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];
	bn_t r, s, d;
	ec_t p;

	bn_null(r);
	bn_null(s);
	bn_null(d);
	ec_null(p);

	bn_new(r);
	bn_new(s);
	bn_new(d);
	ec_new(p);

	BENCH_RUN("cp_ecdsa_gen") {
		BENCH_ADD(cp_ecdsa_gen(d, p));
	}
	BENCH_END;

	BENCH_RUN("cp_ecdsa_sign (h = 0)") {
		BENCH_ADD(cp_ecdsa_sig(r, s, msg, 5, 0, d));
	}
	BENCH_END;

	BENCH_RUN("cp_ecdsa_sign (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_ecdsa_sig(r, s, h, RLC_MD_LEN, 1, d));
	}
	BENCH_END;

	BENCH_RUN("cp_ecdsa_ver (h = 0)") {
		BENCH_ADD(cp_ecdsa_ver(r, s, msg, 5, 0, p));
	}
	BENCH_END;

	BENCH_RUN("cp_ecdsa_ver (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_ecdsa_ver(r, s, h, RLC_MD_LEN, 1, p));
	}
	BENCH_END;

	bn_free(r);
	bn_free(s);
	bn_free(d);
	ec_free(p);
}

static void ecss(void) {
	uint8_t msg[5] = { 0, 1, 2, 3, 4 };
	bn_t r, s, d;
	ec_t p;

	bn_null(r);
	bn_null(s);
	bn_null(d);
	ec_null(p);

	bn_new(r);
	bn_new(s);
	bn_new(d);
	ec_new(p);

	BENCH_RUN("cp_ecss_gen") {
		BENCH_ADD(cp_ecss_gen(d, p));
	}
	BENCH_END;

	BENCH_RUN("cp_ecss_sign") {
		BENCH_ADD(cp_ecss_sig(r, s, msg, 5, d));
	}
	BENCH_END;

	BENCH_RUN("cp_ecss_ver") {
		BENCH_ADD(cp_ecss_ver(r, s, msg, 5, p));
	}
	BENCH_END;

	bn_free(r);
	bn_free(s);
	bn_free(d);
	ec_free(p);
}

static void vbnn(void) {
	uint8_t ida[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
	uint8_t idb[] = { 5, 6, 7, 8, 9, 0, 1, 2, 3, 4 };
	bn_t msk, ska, skb;
	ec_t mpk, pka, pkb;

	uint8_t m[] = "Thrice the brinded cat hath mew'd.";

	ec_t r;
	bn_t z;
	bn_t h;

	bn_null(z);
	bn_null(h);
	bn_null(msk);
	bn_null(ska);
	bn_null(skb);
	ec_null(r);
	ec_null(mpk);
	bn_null(pka);
	bn_null(pkb);

	bn_new(z);
	bn_new(h);
	bn_new(msk);
	bn_new(ska);
	bn_new(skb);
	ec_new(r);
	ec_new(mpk);
	ec_new(pka);
	ec_new(pkb);

	BENCH_RUN("cp_vbnn_gen") {
		BENCH_ADD(cp_vbnn_gen(msk, mpk));
	}
	BENCH_END;

	BENCH_RUN("cp_vbnn_gen_prv") {
		BENCH_ADD(cp_vbnn_gen_prv(ska, pka, msk, ida, sizeof(ida)));
	}
	BENCH_END;

	cp_vbnn_gen_prv(skb, pkb, msk, idb, sizeof(idb));

	BENCH_RUN("cp_vbnn_sig") {
		BENCH_ADD(cp_vbnn_sig(r, z, h, ida, sizeof(ida), m, sizeof(m), ska, pka));
	}
	BENCH_END;

	BENCH_RUN("cp_vbnn_ver") {
		BENCH_ADD(cp_vbnn_ver(r, z, h, ida, sizeof(ida), m, sizeof(m), mpk));
	}
	BENCH_END;

	bn_free(z);
	bn_free(h);
	bn_free(msk);
	bn_free(ska);
	bn_free(skb);
	ec_free(r);
	ec_free(mpk);
	ec_free(pka);
	ec_free(pkb);
}

#define MAX_KEYS	RLC_MAX(BENCH, 16)
#define MIN_KEYS	RLC_MIN(BENCH, 16)

static void ers(void) {
	size_t size;
	ec_t pp, pk[MAX_KEYS + 1];
	bn_t sk[MAX_KEYS + 1], td;
	ers_t ring[MAX_KEYS + 1];
	const uint8_t m[5] = { 0, 1, 2, 3, 4 };

	bn_null(td);
	ec_null(pp);

	bn_new(td);
	ec_new(pp);
	for (int i = 0; i <= MAX_KEYS; i++) {
		bn_null(sk[i]);
		bn_new(sk[i]);
		ec_null(pk[i]);
		ec_new(pk[i]);
		ers_null(ring[i]);
		ers_new(ring[i]);
		cp_ers_gen_key(sk[i], pk[i]);
	}

	cp_ers_gen(pp);

	BENCH_RUN("cp_ers_sig") {
		BENCH_ADD(cp_ers_sig(td, ring[0], m, 5, sk[0], pk[0], pp));
	} BENCH_END;

	BENCH_RUN("cp_ers_ver") {
		BENCH_ADD(cp_ers_ver(td, ring, 1, m, 5, pp));
	} BENCH_END;

	size = 1;
	BENCH_FEW("cp_ers_ext", cp_ers_ext(td, ring, &size, m, 5, pk[size], pp), 1);

	size = 1;
	cp_ers_sig(td, ring[0], m, 5, sk[0], pk[0], pp);
	for (int j = 1; j < MAX_KEYS && size < BENCH; j = j << 1) {
		for (int k = 0; k < j && size < BENCH; k++) {
			cp_ers_ext(td, ring, &size, m, 5, pk[size], pp);
		}
		cp_ers_ver(td, ring, size, m, 5, pp);
		util_print("(%2d exts) ", j);
		BENCH_FEW("cp_ers_ver", cp_ers_ver(td, ring, size, m, 5, pp), 1);
	}

	bn_free(td);
	ec_free(pp);
	for (int i = 0; i <= MAX_KEYS; i++) {
		bn_free(sk[i]);
		ec_free(pk[i]);
		ers_free(ring[i])
	}
}

static void smlers(void) {
	size_t size;
	ec_t pp, pk[MAX_KEYS + 1];
	bn_t sk[MAX_KEYS + 1], td;
	smlers_t ring[MAX_KEYS + 1];
	const uint8_t m[5] = { 0, 1, 2, 3, 4 };

	bn_null(td);
	ec_null(pp);

	bn_new(td);
	ec_new(pp);
	for (int i = 0; i <= MAX_KEYS; i++) {
		bn_null(sk[i]);
		bn_new(sk[i]);
		ec_null(pk[i]);
		ec_new(pk[i]);
		smlers_null(ring[i]);
		smlers_new(ring[i]);
		cp_ers_gen_key(sk[i], pk[i]);
	}

	cp_ers_gen(pp);

	BENCH_RUN("cp_smlers_sig") {
		BENCH_ADD(cp_smlers_sig(td, ring[0], m, 5, sk[0], pk[0], pp));
	} BENCH_END;

	BENCH_RUN("cp_smlers_ver") {
		BENCH_ADD(cp_smlers_ver(td, ring, 1, m, 5, pp));
	} BENCH_END;

	size = 1;
	BENCH_FEW("cp_smlers_ext", cp_smlers_ext(td, ring, &size, m, 5, pk[size], pp), 1);

	size = 1;
	cp_smlers_sig(td, ring[0], m, 5, sk[0], pk[0], pp);
	for (int j = 1; j < MAX_KEYS && size < BENCH; j = j << 1) {
		for (int k = 0; k < j && size < BENCH; k++) {
			cp_smlers_ext(td, ring, &size, m, 5, pk[size], pp);
		}
		cp_smlers_ver(td, ring, size, m, 5, pp);
		util_print("(%2d exts) ", j);
		BENCH_FEW("cp_smlers_ver", cp_smlers_ver(td, ring, size, m, 5, pp), 1);
	}

	bn_free(td);
	ec_free(pp);
	for (int i = 0; i <= MAX_KEYS; i++) {
		bn_free(sk[i]);
		ec_free(pk[i]);
		smlers_free(ring[i])
	}
}

static void etrs(void) {
	size_t size;
	ec_t pp, pk[MAX_KEYS + 1];
	bn_t sk[MAX_KEYS + 1], td[MAX_KEYS + 1], y[MAX_KEYS + 1];
	etrs_t ring[MAX_KEYS + 1];
	const uint8_t m[5] = { 0, 1, 2, 3, 4 };

	ec_null(pp);
	ec_new(pp);
	for (int i = 0; i <= MAX_KEYS; i++) {
		bn_null(td[i]);
		bn_new(td[i]);
		bn_null(y[i]);
		bn_new(y[i]);
		bn_null(sk[i]);
		bn_new(sk[i]);
		ec_null(pk[i]);
		ec_new(pk[i]);
		etrs_null(ring[i]);
		etrs_new(ring[i]);
		ec_curve_get_ord(sk[i]);
		bn_rand_mod(td[i], sk[i]);
		bn_rand_mod(y[i], sk[i]);
		cp_ers_gen_key(sk[i], pk[i]);
	}

	cp_ers_gen(pp);

	BENCH_FEW("cp_etrs_sig", cp_etrs_sig(td, y, MIN_KEYS, ring[0], m, 5, sk[0], pk[0], pp), 1);

	BENCH_FEW("cp_etrs_ver", cp_etrs_ver(1, td, y, MIN_KEYS, ring, 1, m, 5, pp), 1);

	size = 1;
	BENCH_FEW("cp_etrs_ext", (size = 1, cp_etrs_ext(td, y, MIN_KEYS, ring, &size, m, 5, pk[size], pp)), 1);

	size = 1;
	cp_etrs_sig(td, y, MIN_KEYS, ring[0], m, 5, sk[0], pk[0], pp);
	BENCH_FEW("cp_etrs_uni", cp_etrs_uni(1, td, y, MIN_KEYS, ring, &size, m, 5, sk[size], pk[size], pp), 1);

	size = 1;
	cp_etrs_sig(td, y, MIN_KEYS, ring[0], m, 5, sk[0], pk[0], pp);
	for (int j = 1; j < MIN_KEYS && size < MIN_KEYS; j = j << 1) {
		for (int k = 0; k < j && size < MIN_KEYS; k++) {
			cp_etrs_ext(td, y, MIN_KEYS, ring, &size, m, 5, pk[size], pp);
		}
		cp_etrs_ver(1, td+size-1, y+size-1, MIN_KEYS-size+1, ring, size, m, 5, pp);
		util_print("(%2d exts) ", j);
		BENCH_FEW("cp_etrs_ver", cp_etrs_ver(1, td+size-1, y+size-1, MIN_KEYS-size+1, ring, size, m, 5, pp), 1);
	}

	ec_free(pp);
	for (int i = 0; i <= MAX_KEYS; i++) {
		bn_free(td[i]);
		bn_free(y[i]);
		bn_free(sk[i]);
		ec_free(pk[i]);
		etrs_free(ring[i])
	}
}

static int pedersen(void) {
	int code = RLC_ERR;
	ec_t c, h;
	bn_t r, m, n;

	bn_null(m);
	bn_null(n);
	bn_null(r);
	ec_null(h);
	ec_null(c);

	bn_new(m);
	bn_new(n);
	bn_new(r);
	ec_new(h);
	ec_new(c);

	ec_rand(h);
	ec_curve_get_ord(n);

	do {
		bn_rand_mod(m, n);
	} while (bn_is_zero(m));

	BENCH_RUN("cp_ped_com") {
		bn_rand_mod(m, n);
		BENCH_ADD(cp_ped_com(c, h, r, m))
	} BENCH_END;

	bn_free(m);
	bn_free(n);
	bn_free(r);
	ec_free(h);
	ec_free(c);
	return code;
}

static int oprf(void) {
	int code = RLC_ERR;
	ec_t c, h;
	bn_t r, m, n;

	bn_null(m);
	bn_null(n);
	bn_null(r);
	ec_null(h);
	ec_null(c);

	bn_new(m);
	bn_new(n);
	bn_new(r);
	ec_new(h);
	ec_new(c);

	ec_rand(h);
	ec_curve_get_ord(n);

	do {
		bn_rand_mod(m, n);
	} while (bn_is_zero(m));

	BENCH_RUN("cp_oprf_ask") {
		bn_rand_mod(m, n);
		BENCH_ADD(cp_oprf_ask(c, m, h));
	} BENCH_END;

	BENCH_RUN("cp_oprf_ans") {
		bn_rand_mod(r, n);
		BENCH_ADD(cp_oprf_ans(c, r, c));
	} BENCH_END;

	BENCH_RUN("cp_oprf_res") {
		bn_rand_mod(m, n);
		BENCH_ADD(cp_oprf_ans(c, m, c));
	} BENCH_END;

	bn_free(m);
	bn_free(n);
	bn_free(r);
	ec_free(h);
	ec_free(c);
	return code;
}

#endif /* WITH_EC */

#if defined(WITH_PC)

static void pdpub(void) {
	bn_t t, x, r1, r2;
	g1_t p, u1, v1, w1;
	g2_t q, u2, v2, w2;
	gt_t e, r, g[4];

	bn_null(t);
	bn_null(x);
	bn_null(r1);
	bn_null(r2);
	g1_null(p);
	g1_null(u1);
	g1_null(v1);
	g1_null(w1);
	g2_null(q);
	g2_null(u2);
	g2_null(v2);
	g2_null(w2);
	gt_null(e);
	gt_null(r);
	gt_null(g[0]);
	gt_null(g[1]);
	gt_null(g[2]);
	gt_null(g[3]);

	bn_new(t);
	bn_new(x);
	bn_new(r1);
	bn_new(r2);
	g1_new(p);
	g1_new(u1);
	g1_new(v1);
	g1_new(w1);
	g2_new(q);
	g2_new(u2);
	g2_new(v2);
	g2_new(w2);
	gt_new(e);
	gt_new(r);
	gt_new(g[0]);
	gt_new(g[1]);
	gt_new(g[2]);
	gt_new(g[3]);

	BENCH_RUN("cp_pdpub_gen") {
		BENCH_ADD(cp_pdpub_gen(r1, r2, u1, u2, v2, e));
	} BENCH_END;

	BENCH_RUN("cp_pdpub_ask") {
		g1_rand(p);
		g2_rand(q);
		BENCH_ADD(cp_pdpub_ask(v1, w2, p, q, r1, r2, u1, u2, v2));
	} BENCH_END;

	BENCH_RUN("cp_pdpub_ans") {
		g1_rand(p);
		g2_rand(q);
		BENCH_ADD(cp_pdpub_ans(g, p, q, v1, v2, w2));
	} BENCH_END;

	BENCH_RUN("cp_pdpub_ver") {
		g1_rand(p);
		g2_rand(q);
		pc_map(e, p, q);
		BENCH_ADD(cp_pdpub_ver(r, g, r1, e));
	} BENCH_END;

	BENCH_RUN("cp_lvpub_gen") {
		BENCH_ADD(cp_lvpub_gen(r1, r2, u1, u2, v2, e));
	} BENCH_END;

	BENCH_RUN("cp_lvpub_ask") {
		g1_rand(p);
		g2_rand(q);
		BENCH_ADD(cp_lvpub_ask(v1, w2, r1, p, q, r2, u1, u2, v2));
	} BENCH_END;

	BENCH_RUN("cp_lvpub_ans") {
		g1_rand(p);
		g2_rand(q);
		BENCH_ADD(cp_lvpub_ans(g, p, q, v1, v2, w2));
	} BENCH_END;

	BENCH_RUN("cp_lvpub_ver") {
		g1_rand(p);
		g2_rand(q);
		pc_map(e, p, q);
		BENCH_ADD(cp_lvpub_ver(r, g, r1, e));
	} BENCH_END;

	BENCH_RUN("cp_cades_ask") {
		g1_rand(p);
		g2_rand(q);
		BENCH_ADD(cp_cades_ask(t, u1, u2, e, p, q));
	} BENCH_END;

	BENCH_RUN("cp_cades_ans") {
		g1_rand(p);
		g2_rand(q);
		BENCH_ADD(cp_cades_ans(g, u1, u2, p, q));
	} BENCH_END;

	BENCH_RUN("cp_cades_ver") {
		g1_rand(p);
		g2_rand(q);
		cp_cades_ask(t, u1, u2, e, p, q);
		cp_cades_ans(g, u1, u2, p, q);
		BENCH_ADD(cp_cades_ver(r, g, t, e));
	} BENCH_END;

	BENCH_RUN("cp_amore_gen (1)") {
		BENCH_ADD(cp_amore_gen(r1, e));
	} BENCH_END;

	BENCH_RUN("cp_amore_ask (1)") {
		BENCH_ADD(cp_amore_ask(&r1, &w1, v1, v2, w2, u1, u2, r1, e, &p, &q, 1));
	} BENCH_END;

	BENCH_RUN("cp_amore_ans (1)") {
		BENCH_ADD(cp_amore_ans(g, &w1, v1, v2, w2, &p, &q, 1));
	} BENCH_END;

	BENCH_RUN("cp_amore_ver (1)") {
		BENCH_ADD(cp_amore_ver(g, &r1, e, 1));
	} BENCH_END;

	bn_free(t);
	bn_free(x);
	bn_free(r1);
	bn_free(r2);
	g1_free(p);
	g1_free(u1);
	g1_free(v1);
	g1_free(w1);
	g2_free(q);
	g2_free(u2);
	g2_free(v2);
	g2_free(w2);
	gt_free(e);
	gt_free(r);
	gt_free(g[0]);
	gt_free(g[1]);
	gt_free(g[2]);
	gt_free(g[3]);
}

#define AGGS 	2

static void pdprv(void) {
	bn_t r1, r2[3], ls[AGGS], b[AGGS];
	g1_t p[AGGS], u1[2], v1[3], rs[AGGS];
	g2_t q[AGGS], s[AGGS], qs[AGGS], u2[2], v2[4], w2[4];
	gt_t e[2], r, ts[AGGS + 1], g[RLC_MAX(4, AGGS + 1)];

	bn_null(r1);
	gt_null(r);

	bn_new(r1);
	gt_new(r);
	for (int i = 0; i < 2; i++) {
		g1_null(u1[i]);
		g2_null(u2[i]);
		gt_null(e[i]);
		g1_new(u1[i]);
		g2_new(u2[i]);
		gt_new(e[i]);
	}
	for (int i = 0; i < 3; i++) {
		g1_null(v1[i]);
		bn_null(r2[i]);
		g1_new(v1[i]);
		bn_new(r2[i]);
	}
	for (int i = 0; i < 4; i++) {
		g2_null(v2[i]);
		g2_null(w2[i]);
		g2_new(v2[i]);
		g2_new(w2[i]);
	}
	for (size_t i = 0; i < AGGS; i++) {
		bn_null(b[i]);
		bn_null(ls[i]);
		g1_null(p[i]);
		g2_null(q[i]);
		g1_null(rs[i]);
		g2_null(s[i]);
		g2_null(qs[i]);
		gt_null(ts[i]);
		gt_null(g[i]);
		bn_new(b[i]);
		bn_new(ls[i]);
		g1_new(p[i]);
		g2_new(q[i]);
		g1_rand(p[i]);
		g2_rand(q[i]);
		g1_new(rs[i]);
		g2_new(s[i]);
		g2_new(qs[i]);
		gt_new(ts[i]);
		gt_new(g[i]);
	}
	gt_null(ts[AGGS]);
	gt_null(g[AGGS]);
	gt_new(ts[AGGS]);
	gt_new(g[AGGS]);

	BENCH_RUN("cp_pdprv_gen") {
		BENCH_ADD(cp_pdprv_gen(r1, r2, u1, u2, v2, e));
	} BENCH_END;

	BENCH_RUN("cp_pdprv_ask") {
		g1_rand(p[0]);
		g2_rand(q[0]);
		BENCH_ADD(cp_pdprv_ask(v1, w2, p[0], q[0], r1, r2, u1, u2, v2));
	} BENCH_END;

	BENCH_RUN("cp_pdprv_ans") {
		g1_rand(p[0]);
		g2_rand(q[0]);
		BENCH_ADD(cp_pdprv_ans(g, v1, w2));
	} BENCH_END;

	BENCH_RUN("cp_pdprv_ver") {
		g1_rand(p[0]);
		g2_rand(q[0]);
		BENCH_ADD(cp_pdprv_ver(r, g, r1, e));
	} BENCH_END;

	BENCH_RUN("cp_lvprv_gen") {
		BENCH_ADD(cp_lvprv_gen(r1, r2, u1, u2, v2, e));
	} BENCH_END;

	BENCH_RUN("cp_lvprv_ask") {
		g1_rand(p[0]);
		g2_rand(q[0]);
		BENCH_ADD(cp_lvprv_ask(v1, w2, r1, p[0], q[0], r2, u1, u2, v2));
	} BENCH_END;

	BENCH_RUN("cp_lvprv_ans") {
		g1_rand(p[0]);
		g2_rand(q[0]);
		BENCH_ADD(cp_lvprv_ans(g, v1, w2));
	} BENCH_END;

	BENCH_RUN("cp_lvprv_ver") {
		g1_rand(p[0]);
		g2_rand(q[0]);
		BENCH_ADD(cp_lvprv_ver(r, g, r1, e));
	} BENCH_END;

	BENCH_RUN("cp_pdbat_gen (AGGS)") {
		BENCH_ADD(cp_pdbat_gen(u1[0], u2[0], e[0]));
	} BENCH_END;

	BENCH_RUN("cp_pdbat_ask (AGGS)") {
		BENCH_ADD(cp_pdbat_ask(ls, b, rs, v2[0], u1[0], u2[0], p, q, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_pdbat_ans (AGGS)") {
		BENCH_ADD(cp_pdbat_ans(ts, rs, v2[0], u1[0], p, q, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_pdbat_ver (AGGS)") {
		BENCH_ADD(cp_pdbat_ver(g, ts, b, e[0], AGGS));
	} BENCH_END;

	BENCH_RUN("cp_mvbat_gen (AGGS)") {
		BENCH_ADD(cp_mvbat_gen(ls, u2[0], s, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_mvbat_ask (AGGS)") {
		BENCH_ADD(cp_mvbat_ask(b, qs, s, p, q, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_mvbat_ans (AGGS)") {
		BENCH_ADD(cp_mvbat_ans(ts, g, qs, p, q, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_mvbat_ver (AGGS)") {
		BENCH_ADD(cp_mvbat_ver(g, ts, g, b, ls, u2[0], p, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_amore_ask (AGGS)") {
		BENCH_ADD(cp_amore_ask(ls, rs, v1[0], v2[0], w2[0], u1[0], u2[0], r1, e[0], p, q, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_amore_ans (AGGS)") {
		BENCH_ADD(cp_amore_ans(g, rs, v1[0], v2[0], w2[0], p, q, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_amore_ver (AGGS)") {
		BENCH_ADD(cp_amore_ver(g, ls, e[0], AGGS));
	} BENCH_END;

	bn_free(r1);
	gt_free(r);
	for (int i = 0; i < 2; i++) {
		g1_free(u1[i]);
		g2_free(u2[i]);
		gt_free(e[i]);
	}
	for (int i = 0; i < 3; i++) {
		g1_free(v1[i]);
		bn_free(r2[i]);
	}
	for (int i = 0; i < 4; i++) {
		g2_free(v2[i]);
		g2_free(w2[i]);
	}
	for (size_t i = 0; i < AGGS; i++) {
		bn_free(b[i]);
		bn_free(ls[i]);
		g1_free(p[i]);
		g2_free(q[i]);
		g1_free(rs[i]);
		g2_free(s[i]);
		g2_free(qs[i]);
		gt_free(ts[i]);
		gt_free(g[i]);
	}
	gt_free(ts[AGGS]);
	gt_free(g[AGGS]);
}

static void sokaka(void) {
	sokaka_t k;
	bn_t s;
	uint8_t key1[RLC_MD_LEN];
	char *id_a = "Alice";
	char *id_b = "Bob";

	sokaka_null(k);

	sokaka_new(k);
	bn_new(s);

	BENCH_RUN("cp_sokaka_gen") {
		BENCH_ADD(cp_sokaka_gen(s));
	}
	BENCH_END;

	BENCH_RUN("cp_sokaka_gen_prv") {
		BENCH_ADD(cp_sokaka_gen_prv(k, id_b, s));
	}
	BENCH_END;

	BENCH_RUN("cp_sokaka_key (g1)") {
		BENCH_ADD(cp_sokaka_key(key1, RLC_MD_LEN, id_b, k, id_a));
	}
	BENCH_END;

	if (pc_map_is_type3()) {
		cp_sokaka_gen_prv(k, id_a, s);

		BENCH_RUN("cp_sokaka_key (g2)") {
			BENCH_ADD(cp_sokaka_key(key1, RLC_MD_LEN, id_a, k, id_b));
		}
		BENCH_END;
	}

	sokaka_free(k);
	bn_free(s);
}

static void ibe(void) {
	bn_t s;
	g1_t pub;
	g2_t prv;
	uint8_t in[10], out[10 + 2 * RLC_FP_BYTES + 1];
	char *id = "Alice";
	size_t in_len, out_len;

	bn_null(s);
	g1_null(pub);
	g2_null(prv);

	bn_new(s);
	g1_new(pub);
	g2_new(prv);

	rand_bytes(in, sizeof(in));

	BENCH_RUN("cp_ibe_gen") {
		BENCH_ADD(cp_ibe_gen(s, pub));
	}
	BENCH_END;

	BENCH_RUN("cp_ibe_gen_prv") {
		BENCH_ADD(cp_ibe_gen_prv(prv, id, s));
	}
	BENCH_END;

	BENCH_RUN("cp_ibe_enc") {
		in_len = sizeof(in);
		out_len = in_len + 2 * RLC_FP_BYTES + 1;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_ibe_enc(out, &out_len, in, in_len, id, pub));
		cp_ibe_dec(out, &out_len, out, out_len, prv);
	}
	BENCH_END;

	BENCH_RUN("cp_ibe_dec") {
		in_len = sizeof(in);
		out_len = in_len + 2 * RLC_FP_BYTES + 1;
		rand_bytes(in, sizeof(in));
		cp_ibe_enc(out, &out_len, in, in_len, id, pub);
		BENCH_ADD(cp_ibe_dec(out, &out_len, out, out_len, prv));
	}
	BENCH_END;

	bn_free(s);
	g1_free(pub);
	g2_free(prv);
}

static void bgn(void) {
	g1_t c[2];
	g2_t d[2];
	gt_t e[4];
	bgn_t pub, prv;
	dig_t in;

	g1_null(c[0]);
	g1_null(c[1]);
	g2_null(d[0]);
	g2_null(d[1]);
	bgn_null(pub);
	bgn_null(prv);

	g1_new(c[0]);
	g1_new(c[1]);
	g2_new(d[0]);
	g2_new(d[1]);
	bgn_new(pub);
	bgn_new(prv);
	for (int i = 0; i < 4; i++) {
		gt_null(e[i]);
		gt_new(e[i]);
	}

	BENCH_RUN("cp_bgn_gen") {
		BENCH_ADD(cp_bgn_gen(pub, prv));
	} BENCH_END;

	in = 10;

	BENCH_RUN("cp_bgn_enc1") {
		BENCH_ADD(cp_bgn_enc1(c, in, pub));
		cp_bgn_dec1(&in, c, prv);
	} BENCH_END;

	BENCH_RUN("cp_bgn_dec1 (10)") {
		cp_bgn_enc1(c, in, pub);
		BENCH_ADD(cp_bgn_dec1(&in, c, prv));
	} BENCH_END;

	BENCH_RUN("cp_bgn_enc2") {
		BENCH_ADD(cp_bgn_enc2(d, in, pub));
		cp_bgn_dec2(&in, d, prv);
	} BENCH_END;

	BENCH_RUN("cp_bgn_dec2 (10)") {
		cp_bgn_enc2(d, in, pub);
		BENCH_ADD(cp_bgn_dec2(&in, d, prv));
	} BENCH_END;

	BENCH_RUN("cp_bgn_mul") {
		BENCH_ADD(cp_bgn_mul(e, c, d));
	} BENCH_END;

	BENCH_RUN("cp_bgn_dec (100)") {
		BENCH_ADD(cp_bgn_dec(&in, e, prv));
	} BENCH_END;

	BENCH_RUN("cp_bgn_add") {
		BENCH_ADD(cp_bgn_add(e, e, e));
	} BENCH_END;

	g1_free(c[0]);
	g1_free(c[1]);
	g2_free(d[0]);
	g2_free(d[1]);
	bgn_free(pub);
	bgn_free(prv);
	for (int i = 0; i < 4; i++) {
		gt_free(e[i]);
	}
}

static void bls(void) {
	uint8_t msg[5] = { 0, 1, 2, 3, 4 };
	g1_t s;
	g2_t p;
	bn_t d;

	g1_null(s);
	g2_null(p);
	bn_null(d);

	g1_new(s);
	g2_new(p);
	bn_new(d);

	BENCH_RUN("cp_bls_gen") {
		BENCH_ADD(cp_bls_gen(d, p));
	}
	BENCH_END;

	BENCH_RUN("cp_bls_sign") {
		BENCH_ADD(cp_bls_sig(s, msg, 5, d));
	}
	BENCH_END;

	BENCH_RUN("cp_bls_ver") {
		BENCH_ADD(cp_bls_ver(s, msg, 5, p));
	}
	BENCH_END;

	g1_free(s);
	bn_free(d);
	g2_free(p);
}

static void bbs(void) {
	uint8_t msg[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];
	g1_t s;
	g2_t p;
	gt_t z;
	bn_t d;

	g1_null(s);
	g2_null(p);
	gt_null(z);
	bn_null(d);

	g1_new(s);
	g2_new(p);
	gt_new(z);
	bn_new(d);

	BENCH_RUN("cp_bbs_gen") {
		BENCH_ADD(cp_bbs_gen(d, p, z));
	}
	BENCH_END;

	BENCH_RUN("cp_bbs_sign (h = 0)") {
		BENCH_ADD(cp_bbs_sig(s, msg, 5, 0, d));
	}
	BENCH_END;

	BENCH_RUN("cp_bbs_sign (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_bbs_sig(s, h, RLC_MD_LEN, 1, d));
	}
	BENCH_END;

	BENCH_RUN("cp_bbs_ver (h = 0)") {
		BENCH_ADD(cp_bbs_ver(s, msg, 5, 0, p, z));
	}
	BENCH_END;

	BENCH_RUN("cp_bbs_ver (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_bbs_ver(s, h, RLC_MD_LEN, 1, p, z));
	}
	BENCH_END;

	g1_free(s);
	bn_free(d);
	g2_free(p);
}

static int cls(void) {
	int i, code = RLC_ERR;
	bn_t r, t, u, v, vs[4];
	g1_t a, A, b, B, c, As[4], Bs[4];
	g2_t x, y, z, zs[4];
	uint8_t m[5] = { 0, 1, 2, 3, 4 };
	const uint8_t *ms[5] = {m, m, m, m, m};
	const size_t ls[5] = {sizeof(m), sizeof(m), sizeof(m), sizeof(m), sizeof(m)};

	bn_null(r);
	bn_null(t);
	bn_null(u);
	bn_null(v);
	g1_null(a);
	g1_null(A);
	g1_null(b);
	g1_null(B);
	g1_null(c);
	g2_null(x);
	g2_null(y);
	g2_null(z);
	for (i = 0; i < 4; i++) {
		bn_null(vs[i]);
		g1_null(As[i]);
		g1_null(Bs[i]);
		g2_null(zs[i]);
	}

	bn_new(r);
	bn_new(t);
	bn_new(u);
	bn_new(v);
	g1_new(a);
	g1_new(A);
	g1_new(b);
	g1_new(B);
	g1_new(c);
	g2_new(x);
	g2_new(y);
	g2_new(z);
	for (i = 0; i < 4; i++) {
		bn_new(vs[i]);
		g1_new(As[i]);
		g1_new(Bs[i]);
		g2_new(zs[i]);
	}

	BENCH_RUN("cp_cls_gen") {
		BENCH_ADD(cp_cls_gen(u, v, x, y));
	} BENCH_END;

	BENCH_RUN("cp_cls_sig") {
		BENCH_ADD(cp_cls_sig(a, b, c, m, sizeof(m), u, v));
	} BENCH_END;

	BENCH_RUN("cp_cls_ver") {
		BENCH_ADD(cp_cls_ver(a, b, c, m, sizeof(m), x, y));
	} BENCH_END;

	BENCH_RUN("cp_cli_gen") {
		BENCH_ADD(cp_cli_gen(t, u, v, x, y, z));
	} BENCH_END;

	bn_rand(r, RLC_POS, 2 * pc_param_level());
	BENCH_RUN("cp_cli_sig") {
		BENCH_ADD(cp_cli_sig(a, A, b, B, c, m, sizeof(m), r, t, u, v));
	} BENCH_END;

	BENCH_RUN("cp_cli_ver") {
		BENCH_ADD(cp_cli_ver(a, A, b, B, c, m, sizeof(m), r, x, y, z));
	} BENCH_END;

	BENCH_RUN("cp_clb_gen (5)") {
		BENCH_ADD(cp_clb_gen(t, u, vs, x, y, zs, 5));
	} BENCH_END;

	BENCH_RUN("cp_clb_sig (5)") {
		BENCH_ADD(cp_clb_sig(a, As, b, Bs, c, ms, ls, t, u, vs, 5));
	} BENCH_END;

	BENCH_RUN("cp_clb_ver (5)") {
		BENCH_ADD(cp_clb_ver(a, As, b, Bs, c, ms, ls, x, y, zs, 5));
	} BENCH_END;

	bn_free(r);
	bn_free(t);
	bn_free(u);
	bn_free(v);
	g1_free(a);
	g1_free(A);
	g1_free(b);
	g1_free(B);
	g1_free(c);
	g2_free(x);
	g2_free(y);
	g2_free(z);
	for (i = 0; i < 4; i++) {
		bn_free(vs[i]);
		g1_free(As[i]);
		g1_free(Bs[i]);
		g2_free(zs[i]);
	}
	return code;
}

static void pss(void) {
	bn_t ms[10], n, u, v, vs[10];
	g1_t a, b;
	g2_t g, x, y, ys[10];

	bn_null(n);
	bn_null(u);
	bn_null(v);
	g1_null(a);
	g1_null(b);
	g2_null(g);
	g2_null(x);
	g2_null(y);
	bn_new(n);
	bn_new(u);
	bn_new(v);
	g1_new(a);
	g1_new(b);
	g2_new(g);
	g2_new(x);
	g2_new(y);

	g1_get_ord(n);
	for (int i = 0; i < 10; i++) {
		bn_null(ms[i]);
		bn_null(vs[i]);
		g2_null(ys[i]);
		bn_new(ms[i]);
		bn_rand_mod(ms[i], n);
		bn_new(vs[i]);
		g2_new(ys[i]);
	}

	BENCH_RUN("cp_pss_gen") {
		BENCH_ADD(cp_pss_gen(u, v, g, x, y));
	} BENCH_END;

	BENCH_RUN("cp_pss_sig") {
		BENCH_ADD(cp_pss_sig(a, b, ms[0], u, v));
	} BENCH_END;

	BENCH_RUN("cp_pss_ver") {
		BENCH_ADD(cp_pss_ver(a, b, ms[0], g, x, y));
	} BENCH_END;

	BENCH_RUN("cp_psb_gen (10)") {
		BENCH_ADD(cp_psb_gen(u, vs, g, x, ys, 10));
	} BENCH_END;

	BENCH_RUN("cp_psb_sig (10)") {
		BENCH_ADD(cp_psb_sig(a, b, ms, u, vs, 10));
	} BENCH_END;

	BENCH_RUN("cp_psb_ver (10)") {
		BENCH_ADD(cp_psb_ver(a, b, ms, g, x, ys, 10));
	} BENCH_END;

	bn_free(u);
	bn_free(v);
	g1_free(a);
	g1_free(b);
	g2_free(g);
	g2_free(x);
	g2_free(y);
	for (int i = 0; i < 10; i++) {
		bn_free(ms[i]);
		bn_free(vs[i]);
		g1_free(ys[i]);
	}
}

#if defined(WITH_MPC)

static void mpss(void) {
	bn_t m[2], n, u[2], v[2], ms[10][2], vs[10][2];
	g1_t g, s[2];
	g2_t h, x[2], y[2], ys[10][2];
	gt_t r[2];
	mt_t tri[3][2];
	pt_t t[2];

	bn_null(n);
	g1_null(g);
	g2_null(h);

	bn_new(n);
	g1_new(g);
	g2_new(h);
	for (int i = 0; i < 2; i++) {
		bn_null(m[i]);
		bn_null(u[i]);
		bn_null(v[i]);
		g1_null(s[i]);
		g2_null(x[i]);
		g2_null(y[i]);
		gt_null(r[i]);
		mt_null(tri[0][i]);
		mt_null(tri[1][i]);
		mt_null(tri[2][i]);
		pt_null(t[i]);
		bn_new(m[i]);
		bn_new(u[i]);
		bn_new(v[i]);
		g1_new(s[i]);
		g2_new(x[i]);
		g2_new(y[i]);
		gt_new(r[i]);
		mt_new(tri[0][i]);
		mt_new(tri[1][i]);
		mt_new(tri[2][i]);
		pt_new(t[i]);

		g1_get_ord(n);
		for (int j = 0; j < 10; j++) {
			bn_null(ms[j][i]);
			bn_null(vs[j][i]);
			g2_null(ys[j][i]);
			bn_new(ms[j][i]);
			bn_rand_mod(ms[j][i], n);
			bn_new(vs[j][i]);
			g2_new(ys[j][i]);
		}
	}

	pc_map_tri(t);
	mpc_mt_gen(tri[0], n);
	mpc_mt_gen(tri[1], n);
	mpc_mt_gen(tri[2], n);

	bn_rand_mod(m[0], n);
	bn_rand_mod(m[1], n);
	bn_sub(m[0], m[1], m[0]);
	if (bn_sign(m[0]) == RLC_NEG) {
		bn_add(m[0], m[0], n);
	}
	gt_exp_gen(r[0], tri[2][0]->c);
	gt_exp_gen(r[1], tri[2][1]->c);
	tri[2][0]->bt = &r[0];
	tri[2][1]->bt = &r[1];
	tri[2][0]->ct = &r[0];
	tri[2][1]->ct = &r[1];

	BENCH_RUN("cp_mpss_gen") {
		BENCH_ADD(cp_mpss_gen(u, v, h, x, y));
	} BENCH_END;

	BENCH_RUN("cp_mpss_bct") {
		BENCH_ADD(cp_mpss_bct(x, y));
	} BENCH_END;

	BENCH_RUN("cp_mpss_sig") {
		BENCH_ADD(cp_mpss_sig(g, s, m, u, v, tri[0], tri[1]));
	} BENCH_DIV(2);

	BENCH_RUN("cp_mpss_ver") {
		BENCH_ADD(cp_mpss_ver(r[0], g, s, m, h, x[0], y[0], tri[2], t));
	} BENCH_DIV(2);

	g1_get_ord(n);
	pc_map_tri(t);
	mpc_mt_gen(tri[0], n);
	mpc_mt_gen(tri[1], n);
	mpc_mt_gen(tri[2], n);

	BENCH_RUN("cp_mpsb_gen (10)") {
		BENCH_ADD(cp_mpsb_gen(u, vs, h, x, ys, 10));
	} BENCH_END;

	BENCH_RUN("cp_mpsb_bct (10)") {
		BENCH_ADD(cp_mpsb_bct(x, ys, 10));
	} BENCH_END;

	BENCH_RUN("cp_mpsb_sig (10)") {
		BENCH_ADD(cp_mpsb_sig(g, s, ms, u, vs, tri[0], tri[1], 10));
	} BENCH_DIV(2);

	BENCH_RUN("cp_mpsb_ver (10)") {
		BENCH_ADD(cp_mpsb_ver(r[1], g, s, ms, h, x[0], ys, NULL, tri[2], t, 10));
	} BENCH_DIV(2);

	BENCH_RUN("cp_mpsb_ver (10,sk)") {
		BENCH_ADD(cp_mpsb_ver(r[1], g, s, ms, h, x[0], ys, vs, tri[2], t, 10));
	} BENCH_DIV(2);

	bn_free(n);
	g1_free(g);
	g2_free(h);
	for (int i = 0; i < 2; i++) {
		bn_free(m[i]);
		bn_free(u[i]);
		bn_free(v[i]);
		g1_free(s[i]);
		g2_free(x[i]);
		g2_free(y[i]);
		gt_null(r[i]);
		mt_free(tri[0][i]);
		mt_free(tri[1][i]);
		mt_free(tri[2][i]);
		pt_free(t[i]);
		for (int j = 0; j < 10; j++) {
			bn_free(ms[j][i]);
			bn_free(vs[j][i]);
			g2_free(ys[j][i]);
		}
	}
}

#endif

static void zss(void) {
	uint8_t msg[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];
	g1_t p;
	g2_t s;
	gt_t z;
	bn_t d;

	bn_null(d);
	g1_null(p);
	g2_null(s);
	gt_null(z);

	g1_new(p);
	g2_new(s);
	gt_new(z);
	bn_new(d);

	BENCH_RUN("cp_zss_gen") {
		BENCH_ADD(cp_zss_gen(d, p, z));
	}
	BENCH_END;

	BENCH_RUN("cp_zss_sig (h = 0)") {
		BENCH_ADD(cp_zss_sig(s, msg, 5, 0, d));
	}
	BENCH_END;

	BENCH_RUN("cp_zss_sig (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_zss_sig(s, h, RLC_MD_LEN, 1, d));
	}
	BENCH_END;

	BENCH_RUN("cp_zss_ver (h = 0)") {
		BENCH_ADD(cp_zss_ver(s, msg, 5, 0, p, z));
	}
	BENCH_END;

	BENCH_RUN("cp_zss_ver (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_zss_ver(s, h, RLC_MD_LEN, 1, p, z));
	}
	BENCH_END;

	bn_free(d);
	g1_free(p);
	g2_free(s);
}

/* Size of the dataset for benchmarking. */
#define S	10			/* Number of signers. */
#define L	16			/* Number of labels, must be <= RLC_TERMS. */
#define K	RLC_MD_LEN	/* Size of PRF key. */
//#define BENCH_LHS		/* Uncomment for fine-grained benchmarking. */

static void lhs(void) {
	uint8_t k[S][K];
	bn_t m, n, msg[L], sk[S], d[S], x[S][L];
	g1_t _r, h, as[S], cs[S], sig[S];
	g1_t a[S][L], c[S][L], r[S][L];
	g2_t _s, s[S][L], pk[S], y[S], z[S];
	gt_t *hs[S], vk;
	const char *data = "id";
	const char *id[S] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"};
	dig_t ft[S], *f[S];
	size_t flen[S];
	int label[L];

	bn_null(m);
	bn_null(n);
	g1_null(h);
	g1_null(_r);
	g2_null(_s);
	gt_null(vk);

	bn_new(m);
	bn_new(n);
	g1_new(h);
	g1_new(_r);
	g2_new(_s);
	gt_new(vk);

	pc_get_ord(n);
	for (int i = 0; i < L; i++) {
		bn_null(msg[i]);
		bn_new(msg[i]);
		bn_rand_mod(msg[i], n);
	}
	for (int i = 0; i < S; i++) {
		hs[i] = RLC_ALLOCA(gt_t, RLC_TERMS);
		for (int j = 0; j < RLC_TERMS; j++) {
			gt_null(hs[i][j]);
			gt_new(hs[i][j]);
		}
		for (int j = 0; j < L; j++) {
			bn_null(x[i][j]);
			g1_null(a[i][j]);
			g1_null(c[i][j]);
			g1_null(r[i][j]);
			g2_null(s[i][j]);
			bn_new(x[i][j]);
			g1_new(a[i][j]);
			g1_new(c[i][j]);
			g1_new(r[i][j]);
			g2_new(s[i][j]);
		}
		bn_null(sk[i]);
		bn_null(d[i]);
		g1_null(sig[i]);
		g1_null(as[i]);
		g1_null(cs[i]);
		g2_null(y[i]);
		g2_null(z[i]);
		g2_null(pk[i]);

		bn_new(sk[i]);
		bn_new(d[i]);
		g1_new(sig[i]);
		g1_new(as[i]);
		g1_new(cs[i]);
		g2_new(y[i]);
		g2_new(z[i]);
		g2_new(pk[i]);
	}

	/* Define linear function. */
	for (int i = 0; i < S; i++) {
		f[i] = RLC_ALLOCA(dig_t, RLC_TERMS);
		for (int j = 0; j < RLC_TERMS; j++) {
			uint32_t t;
			rand_bytes((uint8_t *)&t, sizeof(uint32_t));
			f[i][j] = t;
		}
		flen[i] = L;
	}

	/* Initialize scheme for messages of single components. */
	cp_cmlhs_init(h);

	BENCH_ONE("cp_cmlhs_gen (ecdsa)",
		for (int j = 0; j < S; j++) {
			cp_cmlhs_gen(x[j], hs[j], L, k[j], K, sk[j], pk[j], d[j], y[j], 0);
		},
	S);

	BENCH_FEW("cp_cmlhs_sig (ecdsa)",
		/* Compute all signatures. */
		for (int j = 0; j < S; j++) {
			for (int l = 0; l < L; l++) {
				label[l] = l;
				bn_mod(msg[l], msg[l], n);
				cp_cmlhs_sig(sig[j], z[j], a[j][l], c[j][l], r[j][l], s[j][l],
					msg[l], data, label[l], x[j][l], h, k[j], K, d[j], sk[j], 0);
			}
		},
	S * L);

	BENCH_RUN("cp_cmlhs_fun") {
		for (int j = 0; j < S; j++) {
			BENCH_ADD(cp_cmlhs_fun(as[j], cs[j], a[j], c[j], f[j], L));
		}
	} BENCH_DIV(S);

	BENCH_RUN("cp_cmlhs_evl") {
		cp_cmlhs_evl(_r, _s, r[0], s[0], f[0], L);
		for (int j = 1; j < S; j++) {
			BENCH_ADD(cp_cmlhs_evl(r[0][0], s[0][0], r[j], s[j], f[j], L));
			g1_add(_r, _r, r[0][0]);
			g2_add(_s, _s, s[0][0]);
		}
		g1_norm(_r, _r);
		g2_norm(_s, _s);
	} BENCH_DIV(S);

	bn_zero(m);
	for (int j = 0; j < L; j++) {
		dig_t sum = 0;
		for (int l = 0; l < S; l++) {
			sum += f[l][j];
		}
		bn_mul_dig(msg[j], msg[j], sum);
		bn_add(m, m, msg[j]);
		bn_mod(m, m, n);
	}

	BENCH_RUN("cp_cmlhs_ver (ecdsa)") {
		BENCH_ADD(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, data, h, label,
			(const gt_t **)hs, (const dig_t **)f, flen, y, pk, S, 0));
	} BENCH_DIV(S);

	BENCH_RUN("cp_cmlhs_off") {
		BENCH_ADD(cp_cmlhs_off(vk, h, label, (const gt_t **)hs,
			(const dig_t **)f, flen, S));
	} BENCH_DIV(S);

	BENCH_RUN("cp_cmlhs_onv (ecdsa)") {
		BENCH_ADD(cp_cmlhs_onv(_r, _s, sig, z, as, cs, m, data, h, vk, y,
			pk, S, 0));
	} BENCH_DIV(S);

	BENCH_ONE("cp_cmlhs_gen (bls)",
		for (int j = 0; j < S; j++) {
			cp_cmlhs_gen(x[j], hs[j], L, k[j], K, sk[j], pk[j], d[j], y[j], 1);
		},
	S);

	BENCH_FEW("cp_cmlhs_sig (bls)",
		/* Compute all signatures. */
		for (int j = 0; j < S; j++) {
			for (int l = 0; l < L; l++) {
				label[l] = l;
				bn_mod(msg[l], msg[l], n);
				cp_cmlhs_sig(sig[j], z[j], a[j][l], c[j][l], r[j][l], s[j][l],
					msg[l], data, label[l], x[j][l], h, k[j], K, d[j], sk[j], 1);
			}
		},
	S * L);

	BENCH_RUN("cp_cmlhs_fun") {
		for (int j = 0; j < S; j++) {
			BENCH_ADD(cp_cmlhs_fun(as[j], cs[j], a[j], c[j], f[j], L));
		}
	} BENCH_DIV(S);

	BENCH_RUN("cp_cmlhs_evl") {
		cp_cmlhs_evl(_r, _s, r[0], s[0], f[0], L);
		for (int j = 1; j < S; j++) {
			BENCH_ADD(cp_cmlhs_evl(r[0][0], s[0][0], r[j], s[j], f[j], L));
			g1_add(_r, _r, r[0][0]);
			g2_add(_s, _s, s[0][0]);
		}
		g1_norm(_r, _r);
		g2_norm(_s, _s);
	} BENCH_DIV(S);

	bn_zero(m);
	for (int j = 0; j < L; j++) {
		dig_t sum = 0;
		for (int l = 0; l < S; l++) {
			sum += f[l][j];
		}
		bn_mul_dig(msg[j], msg[j], sum);
		bn_add(m, m, msg[j]);
		bn_mod(m, m, n);
	}

	BENCH_RUN("cp_cmlhs_ver (bls)") {
		BENCH_ADD(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, data, h, label,
			(const gt_t **)hs, (const dig_t **)f, flen, y, pk, S, 1));
	} BENCH_DIV(S);

	BENCH_RUN("cp_cmlhs_off") {
		BENCH_ADD(cp_cmlhs_off(vk, h, label, (const gt_t **)hs,
			(const dig_t **)f, flen, S));
	} BENCH_DIV(S);

	BENCH_RUN("cp_cmlhs_onv (bls)") {
		BENCH_ADD(cp_cmlhs_onv(_r, _s, sig, z, as, cs, m, data, h, vk, y,
			pk, S, 1));
	} BENCH_DIV(S);

#ifdef BENCH_LHS
	for (int t = 1; t <= S; t++) {
		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_cmlhs_ver") {
			BENCH_ADD(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, data, h, label,
				hs, f, flen, y, pk, t));
		} BENCH_END;

		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_cmlhs_off") {
			BENCH_ADD(cp_cmlhs_off(vk, h, label, hs, f, flen, y, pk, t));
		} BENCH_END;

		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_cmlhs_onv") {
			BENCH_ADD(cp_cmlhs_onv(_r, _s, sig, z, as, cs, m, data, h, vk, y,
				pk, t));
		} BENCH_END;
	}

	for (int t = 1; t <= L; t++) {
		util_print("(%2d lbs) ", t);
		for (int u = 0; u < S; u++) {
			flen[u] = t;
		}
		BENCH_RUN("cp_cmlhs_ver") {
			BENCH_ADD(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, data, h, label,
				hs,	f, flen, y, pk, S));
		} BENCH_END;

		util_print("(%2d lbs) ", t);
		BENCH_RUN("cp_cmlhs_off") {
			BENCH_ADD(cp_cmlhs_off(vk, h, label, hs, f, flen, y, pk, t));
		} BENCH_END;

		util_print("(%2d lbs) ", t);
		BENCH_RUN("cp_cmlhs_onv") {
			BENCH_ADD(cp_cmlhs_onv(_r, _s, sig, z, as, cs, m, data, h, vk, y,
				pk, t));
		} BENCH_END;
	}
#endif  /* BENCH_LHS */

	char *ls[L];

	BENCH_RUN("cp_mklhs_gen") {
		for (int j = 0; j < S; j++) {
			BENCH_ADD(cp_mklhs_gen(sk[j], pk[j]));
		}
	} BENCH_DIV(S);

	BENCH_RUN("cp_mklhs_sig") {
		for (int j = 0; j < S; j++) {
			for (int l = 0; l < L; l++) {
				ls[l] = "l";
				bn_mod(msg[l], msg[l], n);
				BENCH_ADD(cp_mklhs_sig(a[j][l], msg[l], data,
					id[j], ls[l], sk[j]));
			}
		}
	} BENCH_DIV(S * L);

	BENCH_RUN("cp_mklhs_fun") {
		for (int j = 0; j < S; j++) {
			bn_zero(d[j]);
			BENCH_ADD(cp_mklhs_fun(d[j], msg, f[j], L));
		}
	}
	BENCH_DIV(S);

	BENCH_RUN("cp_mklhs_evl") {
		g1_set_infty(_r);
		for (int j = 0; j < S; j++) {
			BENCH_ADD(cp_mklhs_evl(r[0][j], a[j], f[j], L));
			g1_add(_r, _r, r[0][j]);
		}
		g1_norm(_r, _r);
	}
	BENCH_DIV(S);

	bn_zero(m);
	for (int j = 0; j < L; j++) {
		dig_t sum = 0;
		for (int l = 0; l < S; l++) {
			sum += f[l][j];
		}
		bn_mul_dig(msg[j], msg[j], sum);
		bn_add(m, m, msg[j]);
		bn_mod(m, m, n);
	}

	BENCH_RUN("cp_mklhs_ver") {
		BENCH_ADD(cp_mklhs_ver(_r, m, d, data, id, (const char **)ls,
			(const dig_t **)f, flen, pk, S));
	} BENCH_DIV(S);

	BENCH_RUN("cp_mklhs_off") {
		BENCH_ADD(cp_mklhs_off(cs, ft, id, (const char **)ls, (const dig_t **)f,
			flen, S));
	} BENCH_DIV(S);

	BENCH_RUN("cp_mklhs_onv") {
		BENCH_ADD(cp_mklhs_onv(_r, m, d, data, id, cs, ft, pk, S));
	} BENCH_DIV(S);

#ifdef BENCH_LHS
	for (int t = 1; t <= S; t++) {
		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_mklhs_ver") {
			BENCH_ADD(cp_mklhs_ver(_r, m, d, data, id, ls, f, flen, pk, t));
		} BENCH_END;

		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_mklhs_off") {
			BENCH_ADD(cp_mklhs_off(cs, ft, id, ls, f, flen, t));
		} BENCH_END;

		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_mklhs_onv") {
			BENCH_ADD(cp_mklhs_onv(_r, m, d, data, id, cs, ft, pk, t));
		} BENCH_END;
	}

	for (int t = 1; t <= L; t++) {
		util_print("(%2d lbs) ", t);
		for (int u = 0; u < S; u++) {
			flen[u] = t;
		}
		BENCH_RUN("cp_mklhs_ver") {
			BENCH_ADD(cp_mklhs_ver(_r, m, d, data, id, ls, f, flen, pk, S));
		} BENCH_END;

		util_print("(%2d lbs) ", t);
		BENCH_RUN("cp_mklhs_off") {
			BENCH_ADD(cp_mklhs_off(cs, ft, id, ls, f, flen, S));
		} BENCH_END;

		util_print("(%2d lbs) ", t);
		BENCH_RUN("cp_mklhs_onv") {
			BENCH_ADD(cp_mklhs_onv(_r, m, d, data, id, cs, ft, pk, S));
		} BENCH_END;
	}
#endif /* BENCH_LHS */

	bn_free(n);
	bn_free(m);
	g1_free(h);
	g1_free(_r);
	g2_free(_s);
	gt_free(vk);

	for (int i = 0; i < L; i++) {
		bn_free(msg[i]);
	}
	for (int i = 0; i < S; i++) {
		RLC_FREE(f[i]);
		for (int j = 0; j < RLC_TERMS; j++) {
			gt_free(hs[i][j]);
		}
		RLC_FREE(hs[i]);
		for (int j = 0; j < L; j++) {
			bn_free(x[i][j]);
			g1_free(a[i][j]);
			g1_free(c[i][j]);
			g1_free(r[i][j]);
			g2_free(s[i][j]);
		}
		bn_free(sk[i]);
		bn_free(d[i]);
		g1_free(sig[i]);
		g1_free(as[i]);
		g1_free(cs[i]);
		g2_free(y[i]);
		g2_free(z[i]);
		g2_free(pk[i]);
	}
}

#define M	256			/* Number of server messages (larger). */
#define N	8			/* Number of client messages. */

static void psi(void) {
	bn_t g, n, q, r, p[M], x[M], v[N], w[N], y[N], z[M];
	g1_t u[M], ss;
	g2_t d[M + 1], s[M + 1];
	gt_t t[M];
	crt_t crt;
	size_t len;

	bn_new(g);
	bn_new(n);
	bn_new(q);
	bn_new(r);
	g1_new(ss);
	for (int i = 0; i < M; i++) {
		bn_null(p[i]);
		bn_null(x[i]);
		bn_null(z[i]);
		g2_null(d[i]);
		g2_null(s[i]);
		bn_new(p[i]);
		bn_new(x[i]);
		bn_new(z[i]);
		g2_new(d[i]);
		g2_new(s[i]);
	}
	g2_null(d[M]);
	g2_new(d[M]);
	g2_null(s[M]);
	g2_new(s[M]);
	for (int i = 0; i < N; i++) {
		bn_null(v[i]);
		bn_null(w[i]);
		bn_null(y[i]);
		g1_null(u[i]);
		gt_null(t[i]);
		bn_new(v[i]);
		bn_new(w[i]);
		bn_new(y[i]);
		g1_new(u[i]);
		gt_new(t[i]);
	}
	crt_new(crt);

	pc_get_ord(q);
	for (int j = 0; j < M; j++) {
		bn_rand_mod(x[j], q);
	}
	for (int j = 0; j < N; j++) {
		bn_rand_mod(y[j], q);
	}

	BENCH_ONE("cp_rsapsi_gen", cp_rsapsi_gen(g, n, RLC_BN_BITS), 1);

	BENCH_RUN("cp_rsapsi_ask (M)") {
		BENCH_ADD(cp_rsapsi_ask(q, r, p, g, n, x, M));
	} BENCH_END;

	BENCH_RUN("cp_rsapsi_ans (N)") {
		BENCH_ADD(cp_rsapsi_ans(v, w, q, g, n, y, N));
	} BENCH_END;

	BENCH_RUN("cp_rsapsi_int") {
		BENCH_ADD(cp_rsapsi_int(z, &len, r, p, n, x, M, v, w, N));
	} BENCH_END;

	BENCH_ONE("cp_shipsi_gen", cp_shipsi_gen(g, crt, RLC_BN_BITS), 1);

	BENCH_RUN("cp_shipsi_ask (M)") {
		BENCH_ADD(cp_shipsi_ask(q, r, p, g, crt->n, x, M));
	} BENCH_END;

	BENCH_RUN("cp_shipsi_ans (N)") {
		BENCH_ADD(cp_shipsi_ans(v, w[0], q, g, crt, y, N));
	} BENCH_END;

	BENCH_RUN("cp_shipsi_int") {
		BENCH_ADD(cp_shipsi_int(z, &len, r, p, crt->n, x, M, v, w[0], N));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_gen (M)") {
		BENCH_ADD(cp_pbpsi_gen(q, ss, s, M));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_ask (M)") {
		BENCH_ADD(cp_pbpsi_ask(d, r, x, s, M));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_ans (N)") {
		BENCH_ADD(cp_pbpsi_ans(t, u, ss, d[0], y, N));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_int") {
		BENCH_ADD(cp_pbpsi_int(z, &len, d, x, M, t, u, N));
	} BENCH_END;

    bn_free(q);
	bn_free(r);
	g1_free(ss);
	for (int i = 0; i < M; i++) {
		bn_free(x[i]);
		bn_free(z[i]);
		g2_free(d[i]);
		g2_free(s[i]);
	}
	g2_free(d[M]);
	g2_free(s[M]);
	for (int i = 0; i < N; i++) {
		bn_free(y[i]);
		g1_free(u[i]);
		gt_free(t[i]);
	}
}

#endif /* WITH_PC */

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the CP module:", 0);

#if defined(WITH_BN)
	util_banner("Protocols based on integer factorization:\n", 0);
	rsa();
	rabin();
	paillier();
	benaloh();
#endif

#if defined(WITH_EC)
	if (ec_param_set_any() == RLC_OK) {
		util_banner("Protocols based on elliptic curves:\n", 0);
		ecdh();
		ecmqv();
		ecies();
		ecdsa();
		ecss();
		vbnn();
		ers();
		smlers();
		etrs();
		pedersen();
		oprf();
	}
#endif

#if defined(WITH_PC)
	if (pc_param_set_any() == RLC_OK) {
		util_banner("Protocols based on pairings:\n", 0);
		pdpub();
		pdprv();
		sokaka();
		ibe();
		bgn();
		bls();
		bbs();
		cls();
		pss();
#if defined(WITH_MPC)
		mpss();
#endif
		zss();
		lhs();

		util_banner("Protocols based on accumulators:\n", 0);
		psi();
	}
#endif

	core_clean();
	return 0;
}
