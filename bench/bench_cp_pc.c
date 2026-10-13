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
 * Benchmarks for cryptographic protocols based on pairings.
 *
 * @version $Id$
 * @ingroup bench
 */

#include <stdio.h>

#include "relic.h"
#include "relic_bench.h"

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
		BENCH_ADD(cp_pdpub_ask(v1, w2, p, q, r1, r2, u1, u2));
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
		BENCH_ADD(cp_lvpub_ask(v1, w2, r1, p, q, r2, u1, u2));
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
		BENCH_ADD(cp_amore_ask(&r1, &w1, v1, v2, w2, u1, u2, r1, &p, &q, 1));
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
	}
	gt_null(ts[AGGS]);
	gt_new(ts[AGGS]);
	for (size_t i = 0; i < RLC_MAX(4, AGGS + 1); i++) {
		gt_null(g[i]);
		gt_new(g[i]);
	}

	BENCH_RUN("cp_pdprv_gen") {
		BENCH_ADD(cp_pdprv_gen(r1, r2, u1, u2, v2, e));
	} BENCH_END;

	BENCH_RUN("cp_pdprv_ask") {
		g1_rand(p[0]);
		g2_rand(q[0]);
		BENCH_ADD(cp_pdprv_ask(v1, w2, p[0], q[0], r1, r2, u1, v2));
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
		BENCH_ADD(cp_lvprv_ask(v1, w2, r1, p[0], q[0], r2, u1, v2));
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
		BENCH_ADD(cp_mvbat_ask(b, qs, s, q, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_mvbat_ans (AGGS)") {
		BENCH_ADD(cp_mvbat_ans(ts, g, qs, p, q, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_mvbat_ver (AGGS)") {
		BENCH_ADD(cp_mvbat_ver(g, ts, g, b, ls, u2[0], p, AGGS));
	} BENCH_END;

	BENCH_RUN("cp_amore_ask (AGGS)") {
		BENCH_ADD(cp_amore_ask(ls, rs, v1[0], v2[0], w2[0], u1[0], u2[0], r1, p, q, AGGS));
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
	}
	gt_free(ts[AGGS]);
	for (size_t i = 0; i < RLC_MAX(4, AGGS + 1); i++) {
		gt_free(g[i]);
	}
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
	gt_free(z);
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

	bn_free(n);
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
		g2_free(ys[i]);
	}
}

#if defined(WITH_MPC)

static void mpss(void) {
	bn_t m[2], n, u[2], v[2], ms[10][2], vs[10][2];
	g1_t g, s[2];
	g2_t h, x[2], y[2], ys[10][2];
	gt_t r[2];
	mt_t tri[3][2], btri[10][2];
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
		for (int j = 0; j < 10; j++) {
			mt_null(btri[j][i]);
		}
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
		for (int j = 0; j < 10; j++) {
			mt_new(btri[j][i]);
		}
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
		BENCH_ADD(cp_mpss_sig(g, s, m, u, v, tri[0]));
	} BENCH_DIV(2);

	BENCH_RUN("cp_mpss_ver") {
		BENCH_ADD(cp_mpss_ver(r[0], g, s, m, h, x[0], y[0], tri[2]));
	} BENCH_DIV(2);

	g1_get_ord(n);
	pc_map_tri(t);
	mpc_mt_gen(tri[0], n);
	mpc_mt_gen(tri[1], n);
	mpc_mt_gen(tri[2], n);
	for (int j = 0; j < 10; j++) {
		mpc_mt_gen(btri[j], n);
	}

	BENCH_RUN("cp_mpsb_gen (10)") {
		BENCH_ADD(cp_mpsb_gen(u, vs, h, x, ys, 10));
	} BENCH_END;

	BENCH_RUN("cp_mpsb_bct (10)") {
		BENCH_ADD(cp_mpsb_bct(x, ys, 10));
	} BENCH_END;

	BENCH_RUN("cp_mpsb_sig (10)") {
		BENCH_ADD(cp_mpsb_sig(g, s, ms, u, vs, btri, 10));
	} BENCH_DIV(2);

	BENCH_RUN("cp_mpsb_ver (10)") {
		BENCH_ADD(cp_mpsb_ver(r[1], g, s, ms, h, x[0], ys, NULL, NULL, tri[2], 10));
	} BENCH_DIV(2);

	BENCH_RUN("cp_mpsb_ver (10,sk)") {
		BENCH_ADD(cp_mpsb_ver(r[1], g, s, ms, h, x[0], ys, vs, btri, tri[2], 10));
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
		gt_free(r[i]);
		gt_null(r[i]);
		mt_free(tri[0][i]);
		mt_free(tri[1][i]);
		mt_free(tri[2][i]);
		for (int j = 0; j < 10; j++) {
			mt_free(btri[j][i]);
		}
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
	gt_free(z);
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
					msg[l], data, label[l], x[j], h, k[j], K, d[j], sk[j], 0);
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
		BENCH_ADD(cp_cmlhs_off(vk, label, (const gt_t **)hs,
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
					msg[l], data, label[l], x[j], h, k[j], K, d[j], sk[j], 1);
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
		BENCH_ADD(cp_cmlhs_off(vk, label, (const gt_t **)hs,
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
				(const gt_t **)hs, (const dig_t **)f, flen, y, pk, t, 1));
		} BENCH_END;

		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_cmlhs_off") {
			BENCH_ADD(cp_cmlhs_off(vk, label, (const gt_t **)hs,
				(const dig_t **)f, flen, t));
		} BENCH_END;

		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_cmlhs_onv") {
			BENCH_ADD(cp_cmlhs_onv(_r, _s, sig, z, as, cs, m, data, h, vk, y,
				pk, t, 1));
		} BENCH_END;
	}

	for (int t = 1; t <= L; t++) {
		util_print("(%2d lbs) ", t);
		for (int u = 0; u < S; u++) {
			flen[u] = t;
		}
		BENCH_RUN("cp_cmlhs_ver") {
			BENCH_ADD(cp_cmlhs_ver(_r, _s, sig, z, as, cs, m, data, h, label,
				(const gt_t **)hs, (const dig_t **)f, flen, y, pk, S, 1));
		} BENCH_END;

		util_print("(%2d lbs) ", t);
		BENCH_RUN("cp_cmlhs_off") {
			BENCH_ADD(cp_cmlhs_off(vk, label, (const gt_t **)hs,
				(const dig_t **)f, flen, t));
		} BENCH_END;

		util_print("(%2d lbs) ", t);
		BENCH_RUN("cp_cmlhs_onv") {
			BENCH_ADD(cp_cmlhs_onv(_r, _s, sig, z, as, cs, m, data, h, vk, y,
				pk, t, 1));
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
			BENCH_ADD(cp_mklhs_ver(_r, m, d, data, id, (const char **)ls,
				(const dig_t **)f, flen, pk, t));
		} BENCH_END;

		util_print("(%2d ids) ", t);
		BENCH_RUN("cp_mklhs_off") {
			BENCH_ADD(cp_mklhs_off(cs, ft, id, (const char **)ls,
				(const dig_t **)f, flen, t));
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
			BENCH_ADD(cp_mklhs_ver(_r, m, d, data, id, (const char **)ls,
				(const dig_t **)f, flen, pk, S));
		} BENCH_END;

		util_print("(%2d lbs) ", t);
		BENCH_RUN("cp_mklhs_off") {
			BENCH_ADD(cp_mklhs_off(cs, ft, id, (const char **)ls,
				(const dig_t **)f, flen, S));
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

int main(void) {
	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	conf_print();

	util_banner("Benchmarks for the CP module:", 0);

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
	}

	core_clean();
	return 0;
}
