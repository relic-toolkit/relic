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
 * Tests for implementation of cryptographic protocols based on pairings.
 *
 * @version $Id$
 * @ingroup test
 */

#include <stdio.h>

#include "relic.h"
#include "relic_test.h"

static int pdpub(void) {
	int code = RLC_ERR;
	bn_t x, t, r1, r2;
	g1_t p, u1, v1, w1;
	g2_t q, u2, v2, w2;
	gt_t e, r, g[3];

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

	RLC_TRY {
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

		TEST_CASE("delegated pairing with public inputs is correct") {
			g1_rand(p);
			g2_rand(q);
			TEST_ASSERT(cp_cades_ask(t, u1, u2, e, p, q) == RLC_OK, end);
			TEST_ASSERT(cp_cades_ans(g, u1, u2, p, q) == RLC_OK, end);
			TEST_ASSERT(cp_cades_ver(r, g, t, e) == 1, end);
			pc_map(g[0], p, q);
			TEST_ASSERT(gt_cmp(r, g[0]) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("preprocessed pairing computation with public inputs is correct") {
			TEST_ASSERT(cp_pdpub_gen(r1, r2, u1, u2, v2, e) == RLC_OK, end);
			g1_rand(p);
			g2_rand(q);
			TEST_ASSERT(cp_pdpub_ask(v1, w2, p, q, r1, r2, u1, u2) == RLC_OK, end);
			TEST_ASSERT(cp_pdpub_ans(g, p, q, v1, v2, w2) == RLC_OK, end);
			TEST_ASSERT(cp_pdpub_ver(r, g, r1, e) == 1, end);
			pc_map(e, p, q);
			TEST_ASSERT(gt_cmp(r, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("faster delegated pairing with public inputs is correct") {
			TEST_ASSERT(cp_lvpub_gen(r1, r2, u1, u2, v2, e) == RLC_OK, end);
			g1_rand(p);
			g2_rand(q);
			TEST_ASSERT(cp_lvpub_ask(v1, w2, r1, p, q, r2, u1, u2) == RLC_OK, end);
			TEST_ASSERT(cp_lvpub_ans(g, p, q, v1, v2, w2) == RLC_OK, end);
			TEST_ASSERT(cp_lvpub_ver(r, g, r1, e) == 1, end);
			pc_map(e, p, q);
			TEST_ASSERT(gt_cmp(r, e) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("amortized delegated batch pairing is correct") {
			TEST_ASSERT(cp_amore_gen(r1, e) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ask(&r2, &w1, v1, v2, w2, u1, u2, r1, &p, &q, 1) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ans(g, &w1, v1, v2, w2, &p, &q, 1) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ver(g, &r2, e, 1) == 1, end);
			pc_map(e, p, q);
			TEST_ASSERT(gt_cmp(e, g[0]) == RLC_EQ, end);
		} TEST_END;
	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
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
	return code;
}

static int pdprv(void) {
	int code = RLC_ERR;
	bn_t r1, r2[3];
	g1_t p, u1[2], v1[3];
	g2_t q, u2[2], v2[4], w2[4];
	gt_t e[2], r, g[4];

	bn_null(r1);
	g1_null(p);
	g2_null(q);
	gt_null(r);
	for (int i = 0; i < 2; i++) {
		g1_null(u1[i]);
		g2_null(u2[i]);
		gt_null(e[i]);
	}
	for (int i = 0; i < 3; i++) {
		g1_null(v1[i]);
		bn_null(r2[i]);
	}
	for (int i = 0; i < 4; i++) {
		g2_null(v2[i]);
		g2_null(w2[i]);
		gt_null(g[i]);
	}

	RLC_TRY {
		bn_new(r1);
		g1_new(p);
		g2_new(q);
		gt_new(r);
		for (int i = 0; i < 2; i++) {
			g1_new(u1[i]);
			g2_new(u2[i]);
			gt_new(e[i]);
		}
		for (int i = 0; i < 3; i++) {
			g1_new(v1[i]);
			bn_new(r2[i]);
		}
		for (int i = 0; i < 4; i++) {
			g2_new(v2[i]);
			g2_new(w2[i]);
			gt_new(g[i]);
		}

		TEST_CASE("delegated pairing computation with private inputs is correct") {
			TEST_ASSERT(cp_pdprv_gen(r1, r2, u1, u2, v2, e) == RLC_OK, end);
			g1_rand(p);
			g2_rand(q);
			TEST_ASSERT(cp_pdprv_ask(v1, w2, p, q, r1, r2, u1, v2) == RLC_OK, end);
			TEST_ASSERT(cp_pdprv_ans(g, v1, w2) == RLC_OK, end);
			TEST_ASSERT(cp_pdprv_ver(r, g, r1, e) == 1, end);
			pc_map(e[0], p, q);
			TEST_ASSERT(gt_cmp(r, e[0]) == RLC_EQ, end);
		} TEST_END;

		TEST_CASE("faster delegated pairing with private inputs is correct") {
			TEST_ASSERT(cp_lvprv_gen(r1, r2, u1, u2, v2, e) == RLC_OK, end);
			g1_rand(p);
			g2_rand(q);
			TEST_ASSERT(cp_lvprv_ask(v1, w2, r1, p, q, r2, u1, v2) == RLC_OK, end);
			TEST_ASSERT(cp_lvprv_ans(g, v1, w2) == RLC_OK, end);
			TEST_ASSERT(cp_lvprv_ver(r, g, r1, e) == 1, end);
			pc_map(e[0], p, q);
			TEST_ASSERT(gt_cmp(r, e[0]) == RLC_EQ, end);
		} TEST_END;
	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(r1);
	g1_free(p);
	g2_free(q);
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
		gt_free(g[i]);
	}
	return code;
}

#define AGGS 	2

static int pdbat(void) {
	int code = RLC_ERR;
	bn_t r, ls[AGGS], b[AGGS];
	g1_t p[AGGS], rs[AGGS], u1, v1;
	g2_t q[AGGS], s[AGGS], qs[AGGS], u2, v2, w2;
	gt_t e, ts[AGGS + 1], g[AGGS + 1];

	bn_null(r);
	g1_null(u1);
	g1_null(v1);
	g2_null(u2);
	g2_null(v2);
	g2_null(w2);
	gt_null(e);

	RLC_TRY {
		bn_new(r);
		g1_new(u1);
		g1_new(v1);
		g2_new(u2);
		g2_new(v2);
		g2_new(w2);
		gt_new(e);
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

		TEST_CASE("delegated batch pairing is correct") {
			TEST_ASSERT(cp_pdbat_gen(u1, u2, e) == RLC_OK, end);
			TEST_ASSERT(cp_pdbat_ask(ls, b, rs, v2, u1, u2, p, q, AGGS) == RLC_OK, end);
			TEST_ASSERT(cp_pdbat_ans(ts, rs, v2, u1, p, q, AGGS) == RLC_OK, end);
			TEST_ASSERT(cp_pdbat_ver(g, ts, b, e, AGGS) == 1, end);
			for (size_t i = 0; i < AGGS; i++) {
				pc_map(e, p[i], q[i]);
				TEST_ASSERT(gt_cmp(e, g[i]) == RLC_EQ, end);
			}
		} TEST_END;

		TEST_CASE("faster delegated batch pairing is correct") {
			TEST_ASSERT(cp_mvbat_gen(ls, u2, s, AGGS) == RLC_OK, end);
			TEST_ASSERT(cp_mvbat_ask(b, qs, s, q, AGGS) == RLC_OK, end);
			TEST_ASSERT(cp_mvbat_ans(ts, g, qs, p, q, AGGS) == RLC_OK, end);
			TEST_ASSERT(cp_mvbat_ver(g, ts, g, b, ls, u2, p, AGGS) == 1, end);
			for (size_t i = 0; i < AGGS; i++) {
				pc_map(e, p[i], q[i]);
				TEST_ASSERT(gt_cmp(e, g[i]) == RLC_EQ, end);
			}
		} TEST_END;

		TEST_CASE("amortized delegated batch pairing is correct") {
			TEST_ASSERT(cp_amore_gen(r, e) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ask(ls, rs, v1, v2, w2, u1, u2, r, p, q, 1) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ans(g, rs, v1, v2, w2, p, q, 1) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ver(g, ls, e, 1) == 1, end);
			pc_map(e, p[0], q[0]);
			TEST_ASSERT(gt_cmp(e, g[0]) == RLC_EQ, end);
			TEST_ASSERT(cp_amore_gen(r, e) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ask(ls, rs, v1, v2, w2, u1, u2, r, p, q, AGGS) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ans(g, rs, v1, v2, w2, p, q, AGGS) == RLC_OK, end);
			TEST_ASSERT(cp_amore_ver(g, ls, e, AGGS) == 1, end);
			for (size_t i = 0; i < AGGS; i++) {
				pc_map(e, p[i], q[i]);
				TEST_ASSERT(gt_cmp(e, g[i]) == RLC_EQ, end);
			}
		} TEST_END;
	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}

	code = RLC_OK;
  end:
	bn_free(r);
	g1_free(u1);
	g1_free(v1);
	g2_free(u2);
	g2_free(v2);
	g2_free(w2);
	gt_free(e);
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
	return code;
}

static int sokaka(void) {
	int code = RLC_ERR, l = RLC_MD_LEN;
	sokaka_t k;
	bn_t s;
	uint8_t k1[RLC_MD_LEN], k2[RLC_MD_LEN];
	char *ia = "Alice";
	char *ib = "Bob";

	sokaka_null(k);
	bn_null(s);

	RLC_TRY {
		sokaka_new(k);
		bn_new(s);

		cp_sokaka_gen(s);

		TEST_CASE("sakai-ohgishi-kasahara auth key agreement is correct") {
			TEST_ASSERT(cp_sokaka_gen_prv(k, ia, s) == RLC_OK, end);
			TEST_ASSERT(cp_sokaka_key(k1, l, ia, k, ib) == RLC_OK, end);
			TEST_ASSERT(cp_sokaka_gen_prv(k, ib, s) == RLC_OK, end);
			TEST_ASSERT(cp_sokaka_key(k2, l, ib, k, ia) == RLC_OK, end);
			TEST_ASSERT(memcmp(k1, k2, l) == 0, end);
		} TEST_END;

	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	sokaka_free(k);
	bn_free(s);
	return code;
}

static int ibe(void) {
	int code = RLC_ERR;
	bn_t s;
	g1_t pub;
	g2_t prv;
	uint8_t in[10], out[10 + 2 * RLC_FP_BYTES + 1];
	char *id = "Alice";
	size_t il, ol;
	int result;

	bn_null(s);
	g1_null(pub);
	g2_null(prv);

	RLC_TRY {
		bn_new(s);
		g1_new(pub);
		g2_new(prv);

		result = cp_ibe_gen(s, pub);

		TEST_CASE("boneh-franklin identity-based encryption/decryption is correct") {
			TEST_ASSERT(result == RLC_OK, end);
			il = 10;
			ol = il + 2 * RLC_FP_BYTES + 1;
			rand_bytes(in, il);
			TEST_ASSERT(cp_ibe_gen_prv(prv, id, s) == RLC_OK, end);
			TEST_ASSERT(cp_ibe_enc(out, &ol, in, il, id, pub) == RLC_OK, end);
			TEST_ASSERT(cp_ibe_dec(out, &il, out, ol, prv) == RLC_OK, end);
			TEST_ASSERT(memcmp(in, out, il) == 0, end);
		} TEST_END;
	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(s);
	g1_free(pub);
	g2_free(prv);
	return code;
}

static int bgn(void) {
	int result, code = RLC_ERR;
	g1_t c[2], d[2];
	g2_t e[2], f[2];
	gt_t g[4];
	bgn_t pub, prv;
	dig_t in, out, t;

	g1_null(c[0]);
	g1_null(c[1]);
	g1_null(d[0]);
	g1_null(d[1]);
	g2_null(e[0]);
	g2_null(e[1]);
	g2_null(f[0]);
	g2_null(f[1]);
	bgn_null(pub);
	bgn_null(prv);

	RLC_TRY {
		g1_new(c[0]);
		g1_new(c[1]);
		g1_new(d[0]);
		g1_new(d[1]);
		g2_new(e[0]);
		g2_new(e[1]);
		g2_new(f[0]);
		g2_new(f[1]);
		bgn_new(pub);
		bgn_new(prv);
		for (int i = 0; i < 4; i++) {
			gt_null(g[i]);
			gt_new(g[i]);
		}

		result = cp_bgn_gen(pub, prv);

		TEST_CASE("boneh-go-nissim encryption/decryption is correct") {
			TEST_ASSERT(result == RLC_OK, end);

			rand_bytes((unsigned char *)&in, sizeof(dig_t));
			in = in % 11;

			TEST_ASSERT(cp_bgn_enc1(c, in, pub) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_dec1(&out, c, prv) == RLC_OK, end);
			TEST_ASSERT(in == out, end);
			TEST_ASSERT(cp_bgn_enc2(e, in, pub) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_dec2(&out, e, prv) == RLC_OK, end);
			TEST_ASSERT(in == out, end);
		} TEST_END;

		TEST_CASE("boneh-go-nissim encryption is additively homomorphic") {
			rand_bytes((unsigned char *)&in, sizeof(dig_t));
			in = in % 11;
			out = in % 7;
			TEST_ASSERT(cp_bgn_enc1(c, in, pub) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_enc1(d, out, pub) == RLC_OK, end);
			g1_add(c[0], c[0], d[0]);
			g1_add(c[1], c[1], d[1]);
			g1_norm(c[0], c[0]);
			g1_norm(c[1], c[1]);
			TEST_ASSERT(cp_bgn_dec1(&t, c, prv) == RLC_OK, end);
			TEST_ASSERT(in + out == t, end);
			TEST_ASSERT(cp_bgn_enc2(e, in, pub) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_enc2(f, out, pub) == RLC_OK, end);
			g2_add(e[0], e[0], f[0]);
			g2_add(e[1], e[1], f[1]);
			g2_norm(e[0], e[0]);
			g2_norm(e[1], e[1]);
			TEST_ASSERT(cp_bgn_dec2(&t, e, prv) == RLC_OK, end);
			TEST_ASSERT(in + out == t, end);
		} TEST_END;

		TEST_CASE("boneh-go-nissim encryption is multiplicatively homomorphic") {
			rand_bytes((unsigned char *)&in, sizeof(dig_t));
			in = in % 11;
			out = in % 17;
			TEST_ASSERT(cp_bgn_enc1(c, in, pub) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_enc2(e, out, pub) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_enc1(d, out, pub) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_enc2(f, in, pub) == RLC_OK, end);
			in = in * out;
			TEST_ASSERT(cp_bgn_mul(g, c, e) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_dec(&t, g, prv) == RLC_OK, end);
			TEST_ASSERT(in == t, end);
			TEST_ASSERT(cp_bgn_mul(g, d, f) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_dec(&t, g, prv) == RLC_OK, end);
			TEST_ASSERT(in == t, end);
			TEST_ASSERT(cp_bgn_add(g, g, g) == RLC_OK, end);
			TEST_ASSERT(cp_bgn_dec(&t, g, prv) == RLC_OK, end);
			TEST_ASSERT(in + in == t, end);
		} TEST_END;

	} RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	g1_free(c[0]);
	g1_free(c[1]);
	g1_free(d[0]);
	g1_free(d[1]);
	g2_free(e[0]);
	g2_free(e[1]);
	g2_free(f[0]);
	g2_free(f[1]);
	bgn_free(pub);
	bgn_free(prv);
	for (int i = 0; i < 4; i++) {
		gt_free(g[i]);
	}
	return code;
}

static int bls(void) {
	int code = RLC_ERR;
	bn_t d;
	g1_t s[2];
	g2_t q[2];
	uint8_t m[5] = { 0, 1, 2, 3, 4 };
	uint8_t n[5] = { 4, 3, 2, 1, 0 };
	const uint8_t *ms[2] = { m, n };
	const size_t ls[2] = { sizeof(m), sizeof(n) };

	bn_null(d);
	g1_null(s[0]);
	g1_null(s[1]);
	g2_null(q[0]);
	g2_null(q[1]);

	RLC_TRY {
		bn_new(d);
		g1_new(s[0]);
		g1_new(s[1]);
		g2_new(q[0]);
		g2_new(q[1]);

		TEST_CASE("boneh-lynn-schacham short signature is correct") {
			TEST_ASSERT(cp_bls_gen(d, q[0]) == RLC_OK, end);
			TEST_ASSERT(cp_bls_sig(s[0], m, sizeof(m), d) == RLC_OK, end);
			TEST_ASSERT(cp_bls_ver(s[0], m, sizeof(m), q[0]) == 1, end);
			/* Check adversarial signature. */
			memset(m, 0, sizeof(m));
			g2_set_infty(q[0]);
			TEST_ASSERT(cp_bls_ver(s[0], m, sizeof(m), q[0]) == 0, end);
		}
		TEST_END;

		TEST_CASE("boneh-gentry-lynn-schacham aggregate signature is correct") {
			TEST_ASSERT(cp_bls_gen(d, q[0]) == RLC_OK, end);
			TEST_ASSERT(cp_bls_sig(s[0], m, sizeof(m), d) == RLC_OK, end);
			TEST_ASSERT(cp_bls_gen(d, q[1]) == RLC_OK, end);
			TEST_ASSERT(cp_bls_sig(s[1], m, sizeof(m), d) == RLC_OK, end);
			g1_add(s[0], s[0], s[1]);
			g2_add(q[0], q[0], q[1]);
			TEST_ASSERT(cp_bls_ver(s[0], m, sizeof(m), q[0]) == 1, end);
		}
		TEST_END;

		TEST_CASE("boneh-drijvers-neven aggregate signature is correct") {
			g1_set_infty(s[0]);
			g2_set_infty(q[0]);
			TEST_ASSERT(cp_bls_gen(d, q[1]) == RLC_OK, end);
			TEST_ASSERT(cp_bls_sig(s[1], m, sizeof(m), d) == RLC_OK, end);
			TEST_ASSERT(cp_bls_agg_sig(s[0], q[0], s[1], q[1]) == RLC_OK, end);
			TEST_ASSERT(cp_bls_gen(d, q[1]) == RLC_OK, end);
			TEST_ASSERT(cp_bls_sig(s[1], m, sizeof(m), d) == RLC_OK, end);
			TEST_ASSERT(cp_bls_agg_sig(s[0], q[0], s[1], q[1]) == RLC_OK, end);
			/* The aggregate verifies under the aggregate key. */
			TEST_ASSERT(cp_bls_ver(s[0], m, sizeof(m), q[0]) == 1, end);
			m[0] ^= 1;
			TEST_ASSERT(cp_bls_ver(s[0], m, sizeof(m), q[0]) == 0, end);
			m[0] ^= 1;
			g1_set_infty(s[0]);
			g2_set_infty(q[0]);
			TEST_ASSERT(cp_bls_gen(d, q[0]) == RLC_OK, end);
			TEST_ASSERT(cp_bls_sig(s[0], ms[0], ls[0], d) == RLC_OK, end);
			TEST_ASSERT(cp_bls_gen(d, q[1]) == RLC_OK, end);
			TEST_ASSERT(cp_bls_sig(s[1], ms[1], ls[1], d) == RLC_OK, end);
			g1_add(s[0], s[0], s[1]);
			TEST_ASSERT(cp_bls_agg_ver(s[0], ms, ls, 2, q) == 1, end);
			n[0] ^= 1;
			TEST_ASSERT(cp_bls_agg_ver(s[0], ms, ls, 2, q) == 0, end);
			n[0] ^= 1;
			/* Aggregates over repeated messages are rejected. */
			TEST_ASSERT(cp_bls_sig(s[0], ms[1], ls[1], d) == RLC_OK, end);
			g1_add(s[0], s[0], s[1]);
			{
				const uint8_t *dup[2] = { ms[1], ms[1] };
				const size_t dl[2] = { ls[1], ls[1] };
				g2_copy(q[0], q[1]);
				TEST_ASSERT(cp_bls_agg_ver(s[0], dup, dl, 2, q) == 0, end);
			}
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(d);
	g1_free(s[0]);
	g1_free(s[1]);
	g2_free(q[0]);
	g2_free(q[1]);
	return code;
}

static int bbs(void) {
	int code = RLC_ERR;
	bn_t d;
	g1_t s;
	g2_t q;
	gt_t z;
	uint8_t m[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];

	bn_null(d);
	g1_null(s);
	g2_null(q);
	gt_null(z);

	RLC_TRY {
		bn_new(d);
		g1_new(s);
		g2_new(q);
		gt_new(z);

		TEST_CASE("boneh-boyen short signature is correct") {
			TEST_ASSERT(cp_bbs_gen(d, q, z) == RLC_OK, end);
			TEST_ASSERT(cp_bbs_sig(s, m, sizeof(m), 0, d) == RLC_OK, end);
			TEST_ASSERT(cp_bbs_ver(s, m, sizeof(m), 0, q, z) == 1, end);
			md_map(h, m, sizeof(m));
			TEST_ASSERT(cp_bbs_sig(s, m, sizeof(m), 1, d) == RLC_OK, end);
			TEST_ASSERT(cp_bbs_ver(s, m, sizeof(m), 1, q, z) == 1, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(d);
	g1_free(s);
	g2_free(q);
	gt_free(z);
	return code;
}

static int cls(void) {
	int i, code = RLC_ERR;
	bn_t r, t, u, v, vs[4];
	g1_t a, A, b, B, c, As[4], Bs[4];
	g2_t x, y, z, zs[4];
	const uint8_t m[5] = { 0, 1, 2, 3, 4 };
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

	RLC_TRY {
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

		TEST_CASE("camenisch-lysyanskaya simple signature is correct") {
			TEST_ASSERT(cp_cls_gen(u, v, x, y) == RLC_OK, end);
			TEST_ASSERT(cp_cls_sig(a, b, c, m, sizeof(m), u, v) == RLC_OK, end);
			TEST_ASSERT(cp_cls_ver(a, b, c, m, sizeof(m), x, y) == 1, end);
			/* Check adversarial signature. */
			g1_set_infty(a);
			g1_set_infty(b);
			g1_set_infty(c);
			TEST_ASSERT(cp_cls_ver(a, b, c, m, sizeof(m), x, y) == 0, end);
		}
		TEST_END;

		TEST_CASE("camenisch-lysyanskaya message-independent signature is correct") {
			bn_rand(r, RLC_POS, 2 * pc_param_level());
			TEST_ASSERT(cp_cli_gen(t, u, v, x, y, z) == RLC_OK, end);
			TEST_ASSERT(cp_cli_sig(a, A, b, B, c, m, sizeof(m), r, t, u, v)
					== RLC_OK, end);
			TEST_ASSERT(cp_cli_ver(a, A, b, B, c, m, sizeof(m), r, x, y, z)
					== 1, end);
			/* Check adversarial signature. */
			g1_set_infty(a);
			g1_set_infty(A);
			g1_set_infty(b);
			g1_set_infty(B);
			g1_set_infty(c);
			TEST_ASSERT(cp_cli_ver(a, A, b, B, c, m, sizeof(m), r, x, y, z) == 0, end);
		}
		TEST_END;

		TEST_CASE("camenisch-lysyanskaya message-block signature is correct") {
			TEST_ASSERT(cp_clb_gen(t, u, vs, x, y, zs, 5) == RLC_OK, end);
			TEST_ASSERT(cp_clb_sig(a, As, b, Bs, c, ms, ls, t, u, vs, 5)
					== RLC_OK, end);
			TEST_ASSERT(cp_clb_ver(a, As, b, Bs, c, ms, ls, x, y, zs, 5)
					== 1, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
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

static int pss(void) {
	int i, code = RLC_ERR;
	bn_t ms[5], n, u, v, _v[5];
	g1_t a, b;
	g2_t g, x, y, _y[5];

	bn_null(n);
	bn_null(u);
	bn_null(v);
	g1_null(a);
	g1_null(b);
	g2_null(g);
	g2_null(x);
	g2_null(y);

	RLC_TRY {
		bn_new(n);
		bn_new(u);
		bn_new(v);
		g1_new(a);
		g1_new(b);
		g2_new(g);
		g2_new(x);
		g2_new(y);

		g1_get_ord(n);

		for (i = 0; i < 5; i++) {
			bn_null(ms[i]);
			bn_null(_v[i]);
			g2_null(_y[i]);
			bn_new(ms[i]);
			bn_rand_mod(ms[i], n);
			bn_new(_v[i]);
			g2_new(_y[i]);
		}

		TEST_CASE("pointcheval-sanders simple signature is correct") {
			TEST_ASSERT(cp_pss_gen(u, v, g, x, y) == RLC_OK, end);
			TEST_ASSERT(cp_pss_sig(a, b, ms[0], u, v) == RLC_OK, end);
			TEST_ASSERT(cp_pss_ver(a, b, ms[0], g, x, y) == 1, end);
			/* Check adversarial signature. */
			g1_set_infty(a);
			g1_set_infty(b);
			TEST_ASSERT(cp_pss_ver(a, b, ms[0], g, x, y) == 0, end);
		}
		TEST_END;

		TEST_CASE("pointcheval-sanders block signature is correct") {
			TEST_ASSERT(cp_psb_gen(u, _v, g, x, _y, 5) == RLC_OK, end);
			TEST_ASSERT(cp_psb_sig(a, b, ms, u, _v, 5) == RLC_OK, end);
			TEST_ASSERT(cp_psb_ver(a, b, ms, g, x, _y, 5) == 1, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(n);
	bn_free(u);
	bn_free(v);
	g1_free(a);
	g1_free(b);
	g2_free(g);
	g2_free(x);
	g2_free(y);
	for (i = 0; i < 5; i++) {
		bn_free(ms[i]);
		bn_free(_v[i]);
		g2_free(_y[i]);
	}
	return code;
}

#if defined(WITH_MPC)

static int mpss(void) {
	int i, j, code = RLC_ERR;
	bn_t m[2], n, u[2], v[2], ms[5][2], _v[5][2];
	g1_t g, s[2];
	g2_t h, x[2], y[2], _y[5][2];
	gt_t e[2], f[2];
	mt_t tri[3][2], btri[5][2];
	pt_t t[2];

	bn_null(n);
	g1_null(g);
	g2_null(h);

	RLC_TRY {
		bn_new(n);
		g1_new(g);
		g2_new(h);
		g1_get_ord(n);
		for (i = 0; i < 2; i++) {
			bn_null(m[i]);
			bn_null(u[i]);
			bn_null(v[i]);
			g1_null(s[i]);
			g2_null(x[i]);
			g2_null(y[i]);
			gt_null(e[i]);
			gt_null(f[i]);
			mt_null(tri[0][i]);
			mt_null(tri[1][i]);
			mt_null(tri[2][i]);
			for (int j = 0; j < 5; j++) {
				mt_null(btri[j][i]);
			}
			pt_null(t[i]);
			bn_new(m[i]);
			bn_rand_mod(m[i], n);
			bn_new(u[i]);
			bn_new(v[i]);
			g1_new(s[i]);
			g2_new(x[i]);
			g2_new(y[i]);
			gt_new(e[i]);
			gt_new(f[i]);
			mt_new(tri[0][i]);
			mt_new(tri[1][i]);
			mt_new(tri[2][i]);
			for (int j = 0; j < 5; j++) {
				mt_new(btri[j][i]);
			}
			pt_new(t[i]);
			for (j = 0; j < 5; j++) {
				bn_null(ms[j][i]);
				bn_null(_v[j][i]);
				g2_null(_y[j][i]);
				bn_new(ms[j][i]);
				bn_rand_mod(ms[j][i], n);
				bn_new(_v[j][i]);
				g2_new(_y[j][i]);
			}
		}

		TEST_CASE("multi-party pointcheval-sanders simple signature is correct") {
			pc_map_tri(t);
			mpc_mt_gen(tri[0], n);
			mpc_mt_gen(tri[1], n);
			mpc_mt_gen(tri[2], n);
			gt_exp_gen(e[0], tri[2][0]->b);
			gt_exp_gen(e[1], tri[2][1]->b);
			gt_exp_gen(f[0], tri[2][0]->c);
			gt_exp_gen(f[1], tri[2][1]->c);
			tri[2][0]->bt = &e[0];
			tri[2][1]->bt = &e[1];
			tri[2][0]->ct = &f[0];
			tri[2][1]->ct = &f[1];
			TEST_ASSERT(cp_mpss_gen(u, v, h, x, y) == RLC_OK, end);
			TEST_ASSERT(cp_mpss_bct(x, y) == RLC_OK, end);
			/* Compute signature in MPC. */
			TEST_ASSERT(cp_mpss_sig(g, s, m, u, v, tri[0]) == RLC_OK, end);
			/* Verify signature in MPC. */
			TEST_ASSERT(cp_mpss_ver(e[0], g, s, m, h, x[0], y[0], tri[2]) == 1,
				end);
			TEST_ASSERT(gt_is_unity(e[0]) == 1, end);
			/* Check that signature is also valid for conventional scheme. */
			bn_add(m[0], m[0], m[1]);
			bn_mod(m[0], m[0], n);
			g1_add(s[0], s[0], s[1]);
			g1_norm(s[0], s[0]);
			TEST_ASSERT(cp_pss_ver(g, s[0], m[0], h, x[0], y[0]) == 1, end);
		}
		TEST_END;

		TEST_CASE("multi-party pointcheval-sanders block signature is correct") {
			g1_get_ord(n);
			pc_map_tri(t);
			mpc_mt_gen(tri[0], n);
			mpc_mt_gen(tri[1], n);
			mpc_mt_gen(tri[2], n);
			gt_exp_gen(e[0], tri[2][0]->b);
			gt_exp_gen(e[1], tri[2][1]->b);
			gt_exp_gen(f[0], tri[2][0]->c);
			gt_exp_gen(f[1], tri[2][1]->c);
			tri[2][0]->bt = &e[0];
			tri[2][1]->bt = &e[1];
			tri[2][0]->ct = &f[0];
			tri[2][1]->ct = &f[1];
			TEST_ASSERT(cp_mpsb_gen(u, _v, h, x, _y, 5) == RLC_OK, end);
			TEST_ASSERT(cp_mpsb_bct(x, _y, 5) == RLC_OK, end);
			/* Compute signature in MPC. */
			for (int j = 0; j < 5; j++) {
				mpc_mt_gen(btri[j], n);
			}
			TEST_ASSERT(cp_mpsb_sig(g, s, ms, u, _v, btri, 5) == RLC_OK, end);
			/* Verify signature in MPC. The output e[1] is also an element of
			 * the triple, so recompute that element after each call. */
			TEST_ASSERT(cp_mpsb_ver(e[1], g, s, ms, h, x[0], _y, NULL, NULL,
				tri[2], 5) == 1, end);
			gt_exp_gen(e[0], tri[2][0]->b);
			gt_exp_gen(e[1], tri[2][1]->b);
			for (int j = 0; j < 5; j++) {
				mpc_mt_gen(btri[j], n);
			}
			TEST_ASSERT(cp_mpsb_ver(e[1], g, s, ms, h, x[0], _y, _v, btri,
				tri[2], 5) == 1, end);
			gt_exp_gen(e[0], tri[2][0]->b);
			gt_exp_gen(e[1], tri[2][1]->b);
			bn_sub_dig(ms[0][0], ms[0][0], 1);
			for (int j = 0; j < 5; j++) {
				mpc_mt_gen(btri[j], n);
			}
			TEST_ASSERT(cp_mpsb_ver(e[1], g, s, ms, h, x[0], _y, _v, btri,
				tri[2], 5) == 0, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(n);
	g1_free(g);
	g2_free(h);
	for (i = 0; i < 2; i++) {
		bn_free(m[i]);
		bn_free(u[i]);
		bn_free(v[i]);
		g1_free(s[i]);
		g2_free(x[i]);
		g2_free(y[i]);
		gt_free(e[i]);
		gt_free(f[i]);
		mt_free(tri[0][i]);
		mt_free(tri[1][i]);
		mt_free(tri[2][i]);
		for (int j = 0; j < 5; j++) {
			mt_free(btri[j][i]);
		}
		pt_free(t[i]);
		for (j = 0; j < 5; j++) {
			bn_free(ms[j][i]);
			bn_free(_v[j][i]);
			g2_free(_y[j][i]);
		}
	}
	return code;
}

#endif

static int zss(void) {
	int code = RLC_ERR;
	bn_t d;
	g1_t q;
	g2_t s;
	gt_t z;
	uint8_t m[5] = { 0, 1, 2, 3, 4 }, h[RLC_MD_LEN];

	bn_null(d);
	g1_null(q);
	g2_null(s);
	gt_null(z);

	RLC_TRY {
		bn_new(d);
		g1_new(q);
		g2_new(s);
		gt_new(z);

		TEST_CASE("zhang-safavi-naini-susilo signature is correct") {
			TEST_ASSERT(cp_zss_gen(d, q, z) == RLC_OK, end);
			TEST_ASSERT(cp_zss_sig(s, m, sizeof(m), 0, d) == RLC_OK, end);
			TEST_ASSERT(cp_zss_ver(s, m, sizeof(m), 0, q, z) == 1, end);
			md_map(h, m, sizeof(m));
			TEST_ASSERT(cp_zss_sig(s, m, sizeof(m), 1, d) == RLC_OK, end);
			TEST_ASSERT(cp_zss_ver(s, m, sizeof(m), 1, q, z) == 1, end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(d);
	g1_free(q);
	g2_free(s);
	gt_free(z);
	return code;
}

#define S	2			/* Number of signers. */
#define L	4			/* Number of labels. */
#define K	RLC_MD_LEN	/* Size of PRF key. */

static int lhs(void) {
	int code = RLC_ERR;
	uint8_t k[S][K];
	bn_t m, n, msg[S][L], sk[S], d[S], x[S][L];
	g1_t _r, h, as[S], cs[S], sig[S];
	g1_t a[S][L], c[S][L], r[S][L];
	g2_t _s, s[S][L], pk[S], y[S], z[S];
	gt_t *hs[S], vk;
	const char *data = "database-identifier";
	const char *id[S] = { "Alice", "Bob" };
	bn_t ft[S];
	dig_t *f[S] = { NULL };
	size_t flen[S];
	char *ls[L] = { NULL };

	bn_null(m);
	bn_null(n);
	g1_null(h);
	g1_null(_r);
	g2_null(_s);
	gt_null(vk);

	RLC_TRY {
		bn_new(m);
		bn_new(n);
		g1_new(h);
		g1_new(_r);
		g2_new(_s);
		gt_new(vk);

		for (int i = 0; i < S; i++) {
			hs[i] = RLC_ALLOCA(gt_t, RLC_TERMS);
			for (int j = 0; j < RLC_TERMS; j++) {
				gt_null(hs[i][j]);
				gt_new(hs[i][j]);
			}
			for (int j = 0; j < L; j++) {
				bn_null(x[i][j]);
				bn_null(msg[i][j]);
				g1_null(a[i][j]);
				g1_null(c[i][j]);
				g1_null(r[i][j]);
				g2_null(s[i][j]);
				bn_new(x[i][j]);
				bn_new(msg[i][j]);
				g1_new(a[i][j]);
				g1_new(c[i][j]);
				g1_new(r[i][j]);
				g2_new(s[i][j]);
			}
			bn_null(sk[i]);
			bn_null(ft[i]);
			bn_null(d[i]);
			g1_null(sig[i]);
			g1_null(as[i]);
			g1_null(cs[i]);
			g2_null(y[i]);
			g2_null(z[i]);
			g2_null(pk[i]);

			bn_new(sk[i]);
			bn_new(ft[i]);
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
				dig_t t;
				rand_bytes((uint8_t *)&t, sizeof(dig_t));
				f[i][j] = t & RLC_MASK(RLC_DIG / 2);
			}
			flen[i] = L;
		}

		/* Initialize scheme for messages of single components. */
		g1_get_ord(n);
		cp_cmlhs_init(h);

		TEST_CASE("context-hiding linear homomorphic signature is correct") {
			int label[L], b = i % 2;

			for (int j = 0; j < S; j++) {
				cp_cmlhs_gen(x[j], hs[j], L, k[j], K, sk[j], pk[j], d[j], y[j], b);
			}
			/* Compute all signatures (ECDSA if b = 0; BLS if b = 1). */
			for (int j = 0; j < S; j++) {
				for (int l = 0; l < L; l++) {
					label[l] = l;
					bn_rand_mod(msg[j][l], n);
					cp_cmlhs_sig(sig[j], z[j], a[j][l], c[j][l], r[j][l],
						s[j][l], msg[j][l], data, label[l], x[j], h, k[j], K,
						d[j], sk[j], b);
				}
			}
			/* Apply linear function over signatures. */
			for (int j = 0; j < S; j++) {
				cp_cmlhs_fun(as[j], cs[j], a[j], c[j], f[j], flen[j]);
			}

			cp_cmlhs_evl(_r, _s, r[0], s[0], f[0], flen[0]);
			for (int j = 1; j < S; j++) {
				cp_cmlhs_evl(r[0][0], s[0][0], r[j], s[j], f[j], flen[j]);
				g1_add(_r, _r, r[0][0]);
				g2_add(_s, _s, s[0][0]);
			}
			g1_norm(_r, _r);
			g2_norm(_s, _s);
			/* We share messages between users to simplify tests. */
			bn_zero(m);
			for (int j = 0; j < S; j++) {
				for (int l = 0; l < L; l++) {
					bn_mul_dig(msg[j][l], msg[j][l], f[j][l]);
					bn_add(m, m, msg[j][l]);
					bn_mod(m, m, n);
				}
			}

			TEST_ASSERT(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, data, h, label,
				(const gt_t **)hs, (const dig_t **)f, flen, y, pk, S, b), end);

			cp_cmlhs_off(vk, label, (const gt_t **)hs, (const dig_t **)f,
				flen, S);
			TEST_ASSERT(cp_cmlhs_onv(_r, _s, sig, z, as, cs, m, data, h, vk,
				y, pk, S, b) == 1, end);
			/* An aggregate s at infinity is rejected safely. */
			g2_set_infty(_s);
			TEST_ASSERT(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, data, h, label,
				(const gt_t **)hs, (const dig_t **)f, flen, y, pk, S, b) == 0,
				end);
			TEST_ASSERT(cp_cmlhs_onv(_r, _s, sig, z, as, cs, m, data, h, vk,
				y, pk, S, b) == 0, end);
		}
		TEST_END;

		TEST_CASE("simple linear multi-key homomorphic signature is correct") {
			for (int j = 0; j < S; j++) {
				cp_mklhs_gen(sk[j], pk[j]);
				for (int l = 0; l < L; l++) {
					ls[l] = "l";
					bn_rand_mod(msg[j][l], n);
					cp_mklhs_sig(a[j][l], msg[j][l], data, id[j], ls[l], sk[j]);
				}
			}

			for (int j = 0; j < S; j++) {
				cp_mklhs_fun(d[j], msg[j], f[j], L);
			}

			g1_set_infty(_r);
			for (int j = 0; j < S; j++) {
				cp_mklhs_evl(r[0][j], a[j], f[j], L);
				g1_add(_r, _r, r[0][j]);
			}
			g1_norm(_r, _r);

			bn_zero(m);
			for (int j = 0; j < S; j++) {
				for (int l = 0; l < L; l++) {
					bn_mul_dig(msg[j][l], msg[j][l], f[j][l]);
					bn_add(m, m, msg[j][l]);
					bn_mod(m, m, n);
				}
			}

			TEST_ASSERT(cp_mklhs_ver(_r, m, d, data, id, (const char **)ls,
					(const dig_t **)f, flen, pk, S), end);

			cp_mklhs_off(as, ft, id, (const char **)ls, (const dig_t **)f,
					flen, S);
			TEST_ASSERT(cp_mklhs_onv(_r, m, d, data, id, as, ft, pk, S), end);
		}
		TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;

  end:
	bn_free(n);
	bn_free(m);
	g1_free(h);
	g1_free(_r);
	g2_free(_s);
	gt_free(vk);

	for (int i = 0; i < S; i++) {
		RLC_FREE(f[i]);
		for (int j = 0; j < RLC_TERMS; j++) {
			  gt_free(hs[i][j]);
		}
		RLC_FREE(hs[i]);
		for (int j = 0; j < L; j++) {
			bn_free(x[i][j]);
			bn_free(msg[i][j]);
			g1_free(a[i][j]);
			g1_free(c[i][j]);
			g1_free(r[i][j]);
			g2_free(s[i][j]);
		}
		bn_free(sk[i]);
		bn_free(ft[i]);
		bn_free(d[i]);
		g1_free(sig[i]);
		g1_free(as[i]);
		g1_free(cs[i]);
		g2_free(y[i]);
		g2_free(z[i]);
		g2_free(pk[i]);
	}
	return code;
}

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	util_banner("Tests for the CP module", 0);
	util_banner("Protocols based on pairings:\n", 0);

	if (pc_param_set_any() == RLC_OK) {
		if (pdpub() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pdprv() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pdbat() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (sokaka() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (ibe() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (bgn() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (bls() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (bbs() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (cls() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (pss() != RLC_OK) {
			core_clean();
			return 1;
		}

#if defined(WITH_MPC)
		if (mpss() != RLC_OK) {
			core_clean();
			return 1;
		}
#endif

		if (zss() != RLC_OK) {
			core_clean();
			return 1;
		}

		if (lhs() != RLC_OK) {
			core_clean();
			return 1;
		}
	}

	util_banner("All tests have passed.\n", 0);

	core_clean();
	return 0;
}
