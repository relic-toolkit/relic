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
	int out_len, new_len;

	rsa_null(pub);
	rsa_null(prv);

	rsa_new(pub);
	rsa_new(prv);

	BENCH_ONCE("cp_rsa_gen", cp_rsa_gen(pub, prv, RLC_BN_BITS));

	BENCH_BEGIN("cp_rsa_enc") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_enc(out, &out_len, in, sizeof(in), pub));
		cp_rsa_dec(new, &new_len, out, out_len, prv);
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_dec") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
		BENCH_ADD(cp_rsa_dec(new, &new_len, out, out_len, prv));
	} BENCH_END;

#if CP_RSA == BASIC || !defined(STRIP)
	BENCH_ONCE("cp_rsa_gen_basic", cp_rsa_gen_basic(pub, prv, RLC_BN_BITS));

	BENCH_BEGIN("cp_rsa_dec_basic") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len =out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
		BENCH_ADD(cp_rsa_dec_basic(new, &new_len, out, out_len, prv));
	} BENCH_END;
#endif

#if CP_RSA == QUICK || !defined(STRIP)
	BENCH_ONCE("cp_rsa_gen_quick", cp_rsa_gen_quick(pub, prv, RLC_BN_BITS));

	BENCH_BEGIN("cp_rsa_dec_quick") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len =out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_enc(out, &out_len, in, sizeof(in), pub);
		BENCH_ADD(cp_rsa_dec_quick(new, &new_len, out, out_len, prv));
	} BENCH_END;
#endif

	BENCH_ONCE("cp_rsa_gen", cp_rsa_gen(pub, prv, RLC_BN_BITS));

	BENCH_BEGIN("cp_rsa_sig (h = 0)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_sig (h = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		BENCH_ADD(cp_rsa_sig(out, &out_len, h, RLC_MD_LEN, 1, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_ver (h = 0)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		cp_rsa_sig(out, &out_len, in, sizeof(in), 0, prv);
		BENCH_ADD(cp_rsa_ver(out, out_len, in, sizeof(in), 0, pub));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_ver (h = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		cp_rsa_sig(out, &out_len, h, RLC_MD_LEN, 1, prv);
		BENCH_ADD(cp_rsa_ver(out, out_len, h, RLC_MD_LEN, 1, pub));
	} BENCH_END;

#if CP_RSA == BASIC || !defined(STRIP)
	BENCH_ONCE("cp_rsa_gen_basic", cp_rsa_gen_basic(pub, prv, RLC_BN_BITS));

	BENCH_BEGIN("cp_rsa_sig_basic (h = 0)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_sig_basic(out, &out_len, in, sizeof(in), 0, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_sig_basic (h = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		BENCH_ADD(cp_rsa_sig_basic(out, &out_len, h, RLC_MD_LEN, 1, prv));
	} BENCH_END;
#endif

#if CP_RSA == QUICK || !defined(STRIP)
	BENCH_ONCE("cp_rsa_gen_quick", cp_rsa_gen_quick(pub, prv, RLC_BN_BITS));

	BENCH_BEGIN("cp_rsa_sig_quick (h = 0)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_rsa_sig_quick(out, &out_len, in, sizeof(in), 0, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_rsa_sig_quick (h = 1)") {
		out_len = RLC_BN_BITS / 8 + 1;
		new_len = out_len;
		rand_bytes(in, sizeof(in));
		md_map(h, in, sizeof(in));
		BENCH_ADD(cp_rsa_sig_quick(out, &out_len, in, sizeof(in), 1, prv));
	} BENCH_END;
#endif

	rsa_free(pub);
	rsa_free(prv);
}

static void rabin(void) {
	rabin_t pub, prv;
	uint8_t in[1000], new[1000], out[RLC_BN_BITS / 8 + 1];
	int in_len, out_len, new_len;

	rabin_null(pub);
	rabin_null(prv);

	rabin_new(pub);
	rabin_new(prv);

	BENCH_ONCE("cp_rabin_gen", cp_rabin_gen(pub, prv, RLC_BN_BITS));

	BENCH_BEGIN("cp_rabin_enc") {
		in_len = bn_size_bin(pub->n) - 9;
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(in, in_len);
		BENCH_ADD(cp_rabin_enc(out, &out_len, in, in_len, pub));
		cp_rabin_dec(new, &new_len, out, out_len, prv);
	} BENCH_END;

	BENCH_BEGIN("cp_rabin_dec") {
		in_len = bn_size_bin(pub->n) - 9;
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
	int out_len;

	bdpe_null(pub);
	bdpe_null(prv);

	bdpe_new(pub);
	bdpe_new(prv);

	BENCH_ONCE("cp_bdpe_gen", cp_bdpe_gen(pub, prv, bn_get_prime(47), RLC_BN_BITS));

	BENCH_BEGIN("cp_bdpe_enc") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(out, 1);
		in = out[0] % bn_get_prime(47);
		BENCH_ADD(cp_bdpe_enc(out, &out_len, in, pub));
		cp_bdpe_dec(&new, out, out_len, prv);
	} BENCH_END;

	BENCH_BEGIN("cp_bdpe_dec") {
		out_len = RLC_BN_BITS / 8 + 1;
		rand_bytes(out, 1);
		in = out[0] % bn_get_prime(47);
		cp_bdpe_enc(out, &out_len, in, pub);
		BENCH_ADD(cp_bdpe_dec(&new, out, out_len, prv));
	} BENCH_END;

	bdpe_free(pub);
	bdpe_free(prv);
}

static void paillier(void) {
	bn_t n, l;
	uint8_t in[1000], new[1000], out[RLC_BN_BITS / 8 + 1];
	int in_len, out_len;

	bn_null(n);
	bn_null(l);

	bn_new(n);
	bn_new(l);

	BENCH_ONCE("cp_phpe_gen", cp_phpe_gen(n, l, RLC_BN_BITS / 2));

	BENCH_BEGIN("cp_phpe_enc") {
		in_len = bn_size_bin(n);
		out_len = RLC_BN_BITS / 8 + 1;
		memset(in, 0, sizeof(in));
		rand_bytes(in + 1, in_len - 1);
		BENCH_ADD(cp_phpe_enc(out, &out_len, in, in_len, n));
		cp_phpe_dec(new, in_len, out, out_len, n, l);
	} BENCH_END;

	BENCH_BEGIN("cp_phpe_dec") {
		in_len = bn_size_bin(n);
		out_len = RLC_BN_BITS / 8 + 1;
		memset(in, 0, sizeof(in));
		rand_bytes(in + 1, in_len - 1);
		cp_phpe_enc(out, &out_len, in, in_len, n);
		BENCH_ADD(cp_phpe_dec(new, in_len, out, out_len, n, l));
	} BENCH_END;

	bn_free(n);
	bn_free(l);
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

	BENCH_BEGIN("cp_ecdh_gen") {
		BENCH_ADD(cp_ecdh_gen(d, p));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecdh_key") {
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

	BENCH_BEGIN("cp_ecmqv_gen") {
		BENCH_ADD(cp_ecmqv_gen(d1, p1));
	}
	BENCH_END;

	cp_ecmqv_gen(d2, p2);

	BENCH_BEGIN("cp_ecmqv_key") {
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
	int in_len, out_len;

	bn_null(d);
	ec_null(q);
	ec_null(r);

	ec_new(q);
	ec_new(r);
	bn_new(d);

	BENCH_BEGIN("cp_ecies_gen") {
		BENCH_ADD(cp_ecies_gen(d, q));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecies_enc") {
		in_len = sizeof(in);
		out_len = sizeof(out);
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_ecies_enc(r, out, &out_len, in, in_len, q));
		cp_ecies_dec(out, &out_len, r, out, out_len, d);
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecies_dec") {
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

	BENCH_BEGIN("cp_ecdsa_gen") {
		BENCH_ADD(cp_ecdsa_gen(d, p));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecdsa_sign (h = 0)") {
		BENCH_ADD(cp_ecdsa_sig(r, s, msg, 5, 0, d));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecdsa_sign (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_ecdsa_sig(r, s, h, RLC_MD_LEN, 1, d));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecdsa_ver (h = 0)") {
		BENCH_ADD(cp_ecdsa_ver(r, s, msg, 5, 0, p));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecdsa_ver (h = 1)") {
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

	BENCH_BEGIN("cp_ecss_gen") {
		BENCH_ADD(cp_ecss_gen(d, p));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecss_sign") {
		BENCH_ADD(cp_ecss_sig(r, s, msg, 5, d));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ecss_ver") {
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

	BENCH_BEGIN("cp_vbnn_gen") {
		BENCH_ADD(cp_vbnn_gen(msk, mpk));
	}
	BENCH_END;

	BENCH_BEGIN("cp_vbnn_gen_prv") {
		BENCH_ADD(cp_vbnn_gen_prv(ska, pka, msk, ida, sizeof(ida)));
	}
	BENCH_END;

	cp_vbnn_gen_prv(skb, pkb, msk, idb, sizeof(idb));

	BENCH_BEGIN("cp_vbnn_sig") {
		BENCH_ADD(cp_vbnn_sig(r, z, h, ida, sizeof(ida), m, sizeof(m), ska, pka));
	}
	BENCH_END;

	BENCH_BEGIN("cp_vbnn_ver") {
		BENCH_ADD(cp_vbnn_ver(r, z, h, ida, sizeof(ida), m, sizeof(m), mpk));
	}
	BENCH_END;

	bn_free(h);
	bn_free(msk);
	bn_free(ska);
	bn_free(skb);
	ec_free(r);
	ec_free(mpk);
	ec_free(pka);
	ec_free(pkb);
}

#endif /* WITH_EC */

#if defined(WITH_PC)

static void sokaka(void) {
	sokaka_t k;
	bn_t s;
	uint8_t key1[RLC_MD_LEN];
	char id_a[5] = { 'A', 'l', 'i', 'c', 'e' };
	char id_b[3] = { 'B', 'o', 'b' };

	sokaka_null(k);

	sokaka_new(k);
	bn_new(s);

	BENCH_BEGIN("cp_sokaka_gen") {
		BENCH_ADD(cp_sokaka_gen(s));
	}
	BENCH_END;

	BENCH_BEGIN("cp_sokaka_gen_prv") {
		BENCH_ADD(cp_sokaka_gen_prv(k, id_b, sizeof(id_b), s));
	}
	BENCH_END;

	BENCH_BEGIN("cp_sokaka_key (g1)") {
		BENCH_ADD(cp_sokaka_key(key1, RLC_MD_LEN, id_b, sizeof(id_b), k, id_a,
						sizeof(id_a)));
	}
	BENCH_END;

	if (pc_map_is_type3()) {
		cp_sokaka_gen_prv(k, id_a, sizeof(id_a), s);

		BENCH_BEGIN("cp_sokaka_key (g2)") {
			BENCH_ADD(cp_sokaka_key(key1, RLC_MD_LEN, id_a, sizeof(id_a), k, id_b,
							sizeof(id_b)));
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
	char id[5] = { 'A', 'l', 'i', 'c', 'e' };
	int in_len, out_len;

	bn_null(s);
	g1_null(pub);
	g2_null(prv);

	bn_new(s);
	g1_new(pub);
	g2_new(prv);

	rand_bytes(in, sizeof(in));

	BENCH_BEGIN("cp_ibe_gen") {
		BENCH_ADD(cp_ibe_gen(s, pub));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ibe_gen_prv") {
		BENCH_ADD(cp_ibe_gen_prv(prv, id, sizeof(id), s));
	}
	BENCH_END;

	BENCH_BEGIN("cp_ibe_enc") {
		in_len = sizeof(in);
		out_len = in_len + 2 * RLC_FP_BYTES + 1;
		rand_bytes(in, sizeof(in));
		BENCH_ADD(cp_ibe_enc(out, &out_len, in, in_len, id, sizeof(id), pub));
		cp_ibe_dec(out, &out_len, out, out_len, prv);
	}
	BENCH_END;

	BENCH_BEGIN("cp_ibe_dec") {
		in_len = sizeof(in);
		out_len = in_len + 2 * RLC_FP_BYTES + 1;
		rand_bytes(in, sizeof(in));
		cp_ibe_enc(out, &out_len, in, in_len, id, sizeof(id), pub);
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

	BENCH_BEGIN("cp_bgn_gen") {
		BENCH_ADD(cp_bgn_gen(pub, prv));
	} BENCH_END;

	in = 10;

	BENCH_BEGIN("cp_bgn_enc1") {
		BENCH_ADD(cp_bgn_enc1(c, in, pub));
		cp_bgn_dec1(&in, c, prv);
	} BENCH_END;

	BENCH_BEGIN("cp_bgn_dec1 (10)") {
		cp_bgn_enc1(c, in, pub);
		BENCH_ADD(cp_bgn_dec1(&in, c, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_bgn_enc2") {
		BENCH_ADD(cp_bgn_enc2(d, in, pub));
		cp_bgn_dec2(&in, d, prv);
	} BENCH_END;

	BENCH_BEGIN("cp_bgn_dec2 (10)") {
		cp_bgn_enc2(d, in, pub);
		BENCH_ADD(cp_bgn_dec2(&in, d, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_bgn_mul") {
		BENCH_ADD(cp_bgn_mul(e, c, d));
	} BENCH_END;

	BENCH_BEGIN("cp_bgn_dec (100)") {
		BENCH_ADD(cp_bgn_dec(&in, e, prv));
	} BENCH_END;

	BENCH_BEGIN("cp_bgn_add") {
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

	BENCH_BEGIN("cp_bls_gen") {
		BENCH_ADD(cp_bls_gen(d, p));
	}
	BENCH_END;

	BENCH_BEGIN("cp_bls_sign") {
		BENCH_ADD(cp_bls_sig(s, msg, 5, d));
	}
	BENCH_END;

	BENCH_BEGIN("cp_bls_ver") {
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

	BENCH_BEGIN("cp_bbs_gen") {
		BENCH_ADD(cp_bbs_gen(d, p, z));
	}
	BENCH_END;

	BENCH_BEGIN("cp_bbs_sign (h = 0)") {
		BENCH_ADD(cp_bbs_sig(s, msg, 5, 0, d));
	}
	BENCH_END;

	BENCH_BEGIN("cp_bbs_sign (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_bbs_sig(s, h, RLC_MD_LEN, 1, d));
	}
	BENCH_END;

	BENCH_BEGIN("cp_bbs_ver (h = 0)") {
		BENCH_ADD(cp_bbs_ver(s, msg, 5, 0, p, z));
	}
	BENCH_END;

	BENCH_BEGIN("cp_bbs_ver (h = 1)") {
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
	bn_t r, t, u, v, _v[4];
	g1_t a, A, b, B, c, _A[4], _B[4];
	g2_t x, y, z, _z[4];
	uint8_t m[5] = { 0, 1, 2, 3, 4 };
	uint8_t *msgs[5] = {m, m, m, m, m};
	int lens[5] = {sizeof(m), sizeof(m), sizeof(m), sizeof(m), sizeof(m)};

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
		bn_null(_v[i]);
		g1_null(_A[i]);
		g1_null(_B[i]);
		g2_null(_z[i]);
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
		bn_new(_v[i]);
		g1_new(_A[i]);
		g1_new(_B[i]);
		g2_new(_z[i]);
	}

	BENCH_BEGIN("cp_cls_gen") {
		BENCH_ADD(cp_cls_gen(u, v, x, y));
	} BENCH_END;

	BENCH_BEGIN("cp_cls_sig") {
		BENCH_ADD(cp_cls_sig(a, b, c, m, sizeof(m), u, v));
	} BENCH_END;

	BENCH_BEGIN("cp_cls_ver") {
		BENCH_ADD(cp_cls_ver(a, b, c, m, sizeof(m), x, y));
	} BENCH_END;

	BENCH_BEGIN("cp_cli_gen") {
		BENCH_ADD(cp_cli_gen(t, u, v, x, y, z));
	} BENCH_END;

	bn_rand(r, RLC_POS, 2 * pc_param_level());
	BENCH_BEGIN("cp_cli_sig") {
		BENCH_ADD(cp_cli_sig(a, A, b, B, c, m, sizeof(m), r, t, u, v));
	} BENCH_END;

	BENCH_BEGIN("cp_cli_ver") {
		BENCH_ADD(cp_cli_ver(a, A, b, B, c, m, sizeof(m), r, x, y, z));
	} BENCH_END;

	BENCH_BEGIN("cp_clb_gen (5)") {
		BENCH_ADD(cp_clb_gen(t, u, _v, x, y, _z, 5));
	} BENCH_END;

	BENCH_BEGIN("cp_clb_sig (5)") {
		BENCH_ADD(cp_clb_sig(a, _A, b, _B, c, msgs, lens, t, u, _v, 5));
	} BENCH_END;

	BENCH_BEGIN("cp_clb_ver (5)") {
		BENCH_ADD(cp_clb_ver(a, _A, b, _B, c, msgs, lens, x, y, _z, 5));
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
		bn_free(_v[i]);
		g1_free(_A[i]);
		g1_free(_B[i]);
		g2_free(_z[i]);
	}
	return code;
}

static void pss(void) {
	bn_t u, v, _v[5];
	g1_t a, b;
	g2_t g, x, y, _y[5];
	uint8_t m[5] = { 0, 1, 2, 3, 4 };
	uint8_t *msgs[5] = {m, m, m, m, m};
	int i, lens[5] = {sizeof(m), sizeof(m), sizeof(m), sizeof(m), sizeof(m)};

	bn_null(u);
	bn_null(v);
	g1_null(a);
	g1_null(b);
	g2_null(g);
	g2_null(x);
	g2_null(y);
	for (i = 0; i < 5; i++) {
		bn_null(_v[i]);
		g2_null(_y[i]);
	}

	bn_new(u);
	bn_new(v);
	g1_new(a);
	g1_new(b);
	g2_new(g);
	g2_new(x);
	g2_new(y);
	for (i = 0; i < 5; i++) {
		bn_new(_v[i]);
		g2_new(_y[i]);
	}

	BENCH_BEGIN("cp_pss_gen") {
		BENCH_ADD(cp_pss_gen(u, v, g, x, y));
	} BENCH_END;

	BENCH_BEGIN("cp_pss_sig") {
		BENCH_ADD(cp_pss_sig(a, b, m, sizeof(m), u, v));
	} BENCH_END;

	BENCH_BEGIN("cp_pss_ver") {
		BENCH_ADD(cp_pss_ver(a, b, m, sizeof(m), g, x, y));
	} BENCH_END;

	BENCH_BEGIN("cp_psb_gen (5)") {
		BENCH_ADD(cp_psb_gen(u, _v, g, x, _y, 5));
	} BENCH_END;

	BENCH_BEGIN("cp_psb_sig (5)") {
		BENCH_ADD(cp_psb_sig(a, b, msgs, lens, u, _v, 5));
	} BENCH_END;

	BENCH_BEGIN("cp_psb_ver (5)") {
		BENCH_ADD(cp_psb_ver(a, b, msgs, lens, g, x, _y, 5));
	} BENCH_END;

	bn_free(u);
	bn_free(v);
	g1_free(a);
	g1_free(b);
	g2_free(g);
	g2_free(x);
	g2_free(y);
	for (i = 0; i < 5; i++) {
		bn_free(_v[i]);
		g1_free(_y[i]);
	}
}

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

	BENCH_BEGIN("cp_zss_gen") {
		BENCH_ADD(cp_zss_gen(d, p, z));
	}
	BENCH_END;

	BENCH_BEGIN("cp_zss_sign (h = 0)") {
		BENCH_ADD(cp_zss_sig(s, msg, 5, 0, d));
	}
	BENCH_END;

	BENCH_BEGIN("cp_zss_sign (h = 1)") {
		md_map(h, msg, 5);
		BENCH_ADD(cp_zss_sig(s, h, RLC_MD_LEN, 1, d));
	}
	BENCH_END;

	BENCH_BEGIN("cp_zss_ver (h = 0)") {
		BENCH_ADD(cp_zss_ver(s, msg, 5, 0, p, z));
	}
	BENCH_END;

	BENCH_BEGIN("cp_zss_ver (h = 1)") {
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
	gt_t hs[S][RLC_TERMS];
	char *id = "id";
	dig_t ft[S];

	bn_null(m);
	bn_null(n);
	g1_null(h);
	g1_null(_r);
	g2_null(_s);

	bn_new(m);
	bn_new(n);
	g1_new(h);
	g1_new(_r);
	g2_new(_s);

	g1_get_ord(n);
	for (int i = 0; i < L; i++) {
		bn_null(msg[i]);
		bn_new(msg[i]);
		bn_rand_mod(msg[i], n);
	}
	for (int i = 0; i < S; i++) {
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
	dig_t f[S][RLC_TERMS];
	int flen[S];
	for (int i = 0; i < S; i++) {
		for (int j = 0; j < RLC_TERMS; j++) {
			uint32_t t;
			rand_bytes((uint8_t *)&t, sizeof(uint32_t));
			f[i][j] = t;
		}
		flen[i] = L;
	}

	/* Initialize scheme for messages of single components. */
	cp_cmlhs_init(h);

	BENCH_BEGIN("cp_cmlhs_gen") {
		for (int j = 0; j < S; j++) {
			BENCH_ADD(cp_cmlhs_gen(x[j], hs[j], L, k[j], K, sk[j], pk[j], d[j], y[j]));
		}
	} BENCH_DIV(S);

	int label[L];

	BENCH_BEGIN("cp_cmlhs_sig") {
		/* Compute all signatures. */
		for (int j = 0; j < S; j++) {
			for (int l = 0; l < L; l++) {
				label[l] = l;
				bn_mod(msg[l], msg[l], n);
				BENCH_ADD(cp_cmlhs_sig(sig[j], z[j], a[j][l], c[j][l], r[j][l], s[j][l], msg[l],
					id, sizeof(id), label[l], x[j][l], h, k[j], K, d[j], sk[j]));
			}
		}
	} BENCH_DIV(S * L);

	BENCH_BEGIN("cp_cmlhs_fun") {
		for (int j = 0; j < S; j++) {
			BENCH_ADD(cp_cmlhs_fun(as[j], cs[j], a[j], c[j], f[j], L));
		}
	} BENCH_DIV(S);

	BENCH_BEGIN("cp_cmlhs_evl") {
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

	BENCH_BEGIN("cp_cmlhs_ver") {
		BENCH_ADD(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, id, sizeof(id),
			label, h, hs, f, flen, y, pk, S));
	} BENCH_DIV(S);

#ifdef BENCH_LHS
	for (int t = 1; t <= S; t++) {
		util_print("(%2d ids) ", t);
		BENCH_BEGIN("cp_cmlhs_ver") {
			BENCH_ADD(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, id, sizeof(id),
				label, h, hs, f, flen, y, pk, t));
		} BENCH_END;
	}

	for (int t = 1; t <= L; t++) {
		util_print("(%2d lbs) ", t);
		for (int u = 0; u < S; u++) {
			flen[u] = t;
		}
		BENCH_BEGIN("cp_cmlhs_ver") {
			BENCH_ADD(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, id, sizeof(id),
				label, h, hs, f, flen, y, pk, S));
		} BENCH_END;
	}
#endif  /* BENCH_LHS */

	char *ls[L] = { "l" };
	int lens[L] = { sizeof(ls[0]) };

	BENCH_BEGIN("cp_mklhs_gen") {
		for (int j = 0; j < S; j++) {
			BENCH_ADD(cp_mklhs_gen(sk[j], pk[j]));
		}
	} BENCH_DIV(S);

	BENCH_BEGIN("cp_mklhs_sig") {
		for (int j = 0; j < S; j++) {
			for (int l = 0; l < L; l++) {
				bn_mod(msg[l], msg[l], n);
				BENCH_ADD(cp_mklhs_sig(a[j][l], msg[l], id, sizeof(id),
					ls[l], lens[l], sk[j]));
			}
		}
	} BENCH_DIV(S * L);

	BENCH_BEGIN("cp_mklhs_fun") {
		for (int j = 0; j < S; j++) {
			bn_zero(d[j]);
			BENCH_ADD(cp_mklhs_fun(d[j], msg, f[j], L));
		}
	}
	BENCH_DIV(S);

	BENCH_BEGIN("cp_mklhs_evl") {
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

	BENCH_BEGIN("cp_mklhs_ver") {
		BENCH_ADD(cp_mklhs_ver(_r, m, d, id, sizeof(id), ls, lens, f, flen,
			pk, S));
	} BENCH_DIV(S);

	BENCH_BEGIN("cp_mklhs_off") {
		BENCH_ADD(cp_mklhs_off(cs, ft, ls, lens, f, flen, S));
	} BENCH_DIV(S);

	BENCH_BEGIN("cp_mklhs_onv") {
		BENCH_ADD(cp_mklhs_onv(_r, m, d, id, sizeof(id), cs, ft, pk, S));
	} BENCH_DIV(S);

#ifdef BENCH_LHS
	for (int t = 1; t <= S; t++) {
		util_print("(%2d ids) ", t);
		BENCH_BEGIN("cp_mklhs_ver") {
			BENCH_ADD(cp_mklhs_ver(_r, m, d, id, sizeof(id), ls, lens, f, flen,
				pk, t));
		} BENCH_END;
	}

	for (int t = 1; t <= L; t++) {
		util_print("(%2d lbs) ", t);
		for (int u = 0; u < S; u++) {
			flen[u] = t;
		}
		BENCH_BEGIN("cp_mklhs_ver") {
			BENCH_ADD(cp_mklhs_ver(_r, m, d, id, sizeof(id), ls, lens, f, flen,
				pk, S));
		} BENCH_END;
	}

	for (int t = 1; t <= S; t++) {
		util_print("(%2d ids) ", t);
		BENCH_BEGIN("cp_mklhs_off") {
			BENCH_ADD(cp_mklhs_off(cs, ft, ls, lens, f, flen, t));
		} BENCH_END;

		BENCH_BEGIN("cp_mklhs_onv") {
			BENCH_ADD(cp_mklhs_onv(_r, m, d, id, sizeof(id), cs, ft, pk, t));
		} BENCH_END;
	}

	for (int t = 1; t <= L; t++) {
		util_print("(%2d lbs) ", t);
		for (int u = 0; u < S; u++) {
			flen[u] = t;
		}
		BENCH_BEGIN("cp_mklhs_off") {
			BENCH_ADD(cp_mklhs_off(cs, ft, ls, lens, f, flen, S));
		} BENCH_END;

		BENCH_BEGIN("cp_mklhs_onv") {
			BENCH_ADD(cp_mklhs_onv(_r, m, d, id, sizeof(id), cs, ft, pk, S));
		} BENCH_END;
	}
#endif /* BENCH_LHS */

	bn_free(n);
	bn_free(m);
	g1_free(h);
	g1_free(_r);
	g2_free(_s);

	for (int i = 0; i < L; i++) {
		bn_free(msg[i]);
	}
	for (int i = 0; i < S; i++) {
		for (int j = 0; j < RLC_TERMS; j++) {
			gt_free(hs[i][j]);
		}
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
	benaloh();
	paillier();
#endif

#if defined(WITH_EC)
	util_banner("Protocols based on elliptic curves:\n", 0);
	if (ec_param_set_any() == RLC_OK) {
		ecdh();
		ecmqv();
		ecies();
		ecdsa();
		ecss();
		vbnn();
	} else {
		THROW(ERR_NO_CURVE);
	}
#endif

#if defined(WITH_PC)
	util_banner("Protocols based on pairings:\n", 0);
	if (pc_param_set_any() == RLC_OK) {
		sokaka();
		ibe();
		bgn();
		bls();
		bbs();
		cls();
		pss();
		zss();
		lhs();
	} else {
		THROW(ERR_NO_CURVE);
	}
#endif

	core_clean();
	return 0;
}
