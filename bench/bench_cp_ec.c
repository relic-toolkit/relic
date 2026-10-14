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
 * Benchmarks for cryptographic protocols based on elliptic curves.
 *
 * @version $Id$
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

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
	BENCH_FEW("cp_ers_ext", cp_ers_ext(td, ring, &size, m, 5, pk[size]), 1);

	size = 1;
	cp_ers_sig(td, ring[0], m, 5, sk[0], pk[0], pp);
	for (int j = 1; j < MAX_KEYS && size < BENCH; j = j << 1) {
		for (int k = 0; k < j && size < BENCH; k++) {
			cp_ers_ext(td, ring, &size, m, 5, pk[size]);
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
	BENCH_FEW("cp_smlers_ext", cp_smlers_ext(td, ring, &size, m, 5, pk[size]), 1);

	size = 1;
	cp_smlers_sig(td, ring[0], m, 5, sk[0], pk[0], pp);
	for (int j = 1; j < MAX_KEYS && size < BENCH; j = j << 1) {
		for (int k = 0; k < j && size < BENCH; k++) {
			cp_smlers_ext(td, ring, &size, m, 5, pk[size]);
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
	ec_t pp, pk[MAX_KEYS + 1], com[MAX_KEYS + 1];
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
		ec_null(com[i]);
		ec_new(com[i]);
		etrs_null(ring[i]);
		etrs_new(ring[i]);
		ec_curve_get_ord(sk[i]);
		bn_rand_mod(td[i], sk[i]);
		bn_rand_mod(y[i], sk[i]);
		cp_ers_gen_key(sk[i], pk[i]);
	}

	cp_ers_gen(pp);

	BENCH_FEW("cp_etrs_sig", cp_etrs_sig(td, y, MIN_KEYS, ring[0], com, m, 5, sk[0], pk[0], pp), 1);

	BENCH_FEW("cp_etrs_ver", cp_etrs_ver(1, td, y, MIN_KEYS, ring, 1, com, m, 5, pp), 1);

	size = 1;
	BENCH_FEW("cp_etrs_ext", (size = 1, cp_etrs_ext(td, y, MIN_KEYS, ring, &size, com, m, 5, pk[size])), 1);

	size = 1;
	cp_etrs_sig(td, y, MIN_KEYS, ring[0], com, m, 5, sk[0], pk[0], pp);
	BENCH_FEW("cp_etrs_uni", cp_etrs_uni(td, y, MIN_KEYS, ring, &size, com, m, 5, sk[size], pk[size]), 1);

	size = 1;
	cp_etrs_sig(td, y, MIN_KEYS, ring[0], com, m, 5, sk[0], pk[0], pp);
	for (int j = 1; j < MIN_KEYS && size < MIN_KEYS; j = j << 1) {
		for (int k = 0; k < j && size < MIN_KEYS; k++) {
			cp_etrs_ext(td, y, MIN_KEYS, ring, &size, com, m, 5, pk[size]);
		}
		cp_etrs_ver(1, td+size-1, y+size-1, MIN_KEYS-size+1, ring, size, com, m, 5, pp);
		util_print("(%2d exts) ", j);
		BENCH_FEW("cp_etrs_ver", cp_etrs_ver(1, td+size-1, y+size-1, MIN_KEYS-size+1, ring, size, com, m, 5, pp), 1);
	}

	ec_free(pp);
	for (int i = 0; i <= MAX_KEYS; i++) {
		bn_free(td[i]);
		bn_free(y[i]);
		bn_free(sk[i]);
		ec_free(pk[i]);
		ec_free(com[i]);
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

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the CP module:", 0);

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

	core_clean();
	return 0;
}
