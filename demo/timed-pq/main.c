/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Prototype of Timed Post-Quantum Encryption (T-PQ) from "Dual-Timed
 * Cryptosystems": a ciphertext costs tau sequential MinRoot rounds to produce
 * and theta rounds to open, plus a 1/eta fraction of the other delay.
 *
 * The time-asymmetric functions are MinRoot over the 2048-bit safe prime of
 * RFC 3526, the KEM is ML-KEM-1024 (mlkem.c), the AEAD is AES-256-GCM and the
 * random oracles H1 and H2 are SHAKE256, as suggested in the paper.
 *
 * Usage: ./main [tau] [theta]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "relic.h"
#include "mlkem.h"

/** Security parameter in bytes, the length of labels and keys. */
#define LAM			32

/** Maximum message length in bytes. */
#define MSG_MAX		256

/** Length of an element of F_p in bytes. */
#define FP_LEN		(2048 / 8)

/** Length of a KEM ciphertext in bytes. */
#define CT_MAX		MLKEM_CT_LEN

/** Length of the AEAD ciphertext: the message and a GCM tag. */
#define AE_MAX		(MSG_MAX + RLC_BC_LEN)

/** RFC 3526, group 14: a 2048-bit safe prime, congruent to 2 modulo 3. */
static const char *MODP2048 =
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
	"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
	"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
	"98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
	"9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
	"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

/** Public parameters: the MinRoot modulus and the two delays. */
typedef struct {
	bn_t p;
	size_t tau;
	size_t theta;
} tpq_pp_t;

/** A ciphertext (y, w, ct, e). */
typedef struct {
	bn_t y[2];
	bn_t w[2];
	uint8_t ct[CT_MAX];
	size_t ct_len;
	uint8_t e[AE_MAX];
	size_t e_len;
} tpq_ct_t;

/** Wall-clock time in milliseconds. */
static double now(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

/** Appends a pair of elements of F_p as two fixed-length fields. */
static size_t put_pair(uint8_t *buf, const bn_t a, const bn_t b) {
	bn_write_bin(buf, FP_LEN, a);
	bn_write_bin(buf + FP_LEN, FP_LEN, b);
	return 2 * FP_LEN;
}

/**
 * H1(l, w, ct, e) in X_Enc = F_p^2: SHAKE256 with a prefix, each coordinate
 * read from 16 extra bytes and reduced, so that it is close to uniform.
 */
static void h1(bn_t chi0, bn_t chi1, const uint8_t *l, const tpq_ct_t *c,
		const bn_t p) {
	uint8_t in[2 + LAM + 2 * FP_LEN + CT_MAX + AE_MAX];
	uint8_t out[2 * (FP_LEN + 16)];
	size_t len = 0;

	memcpy(in, "H1", 2);
	len += 2;
	memcpy(in + len, l, LAM);
	len += LAM;
	len += put_pair(in + len, c->w[0], c->w[1]);
	memcpy(in + len, c->ct, c->ct_len);
	len += c->ct_len;
	memcpy(in + len, c->e, c->e_len);
	len += c->e_len;
	md_shake256(out, sizeof(out), in, len);
	bn_read_bin(chi0, out, FP_LEN + 16);
	bn_mod(chi0, chi0, p);
	bn_read_bin(chi1, out + FP_LEN + 16, FP_LEN + 16);
	bn_mod(chi1, chi1, p);
}

/** H2(u, kappa, l, ct) in {0, 1}^lambda: SHAKE256 with a prefix. */
static void h2(uint8_t *k, const bn_t u0, const bn_t u1,
		const uint8_t *kappa, const uint8_t *l, const uint8_t *ct,
		size_t ct_len) {
	uint8_t in[2 + 2 * FP_LEN + 2 * LAM + CT_MAX];
	size_t len = 0;

	memcpy(in, "H2", 2);
	len += 2;
	len += put_pair(in + len, u0, u1);
	memcpy(in + len, kappa, LAM);
	len += LAM;
	memcpy(in + len, l, LAM);
	len += LAM;
	memcpy(in + len, ct, ct_len);
	len += ct_len;
	md_shake256(k, LAM, in, len);
}

/** KEM: (kappa, ct) <- ML-KEM.Encaps(ek). */
static int kem_encaps(uint8_t *kappa, uint8_t *ct, size_t *ct_len,
		const uint8_t *ek) {
	*ct_len = MLKEM_CT_LEN;
	return (mlkem_encaps(kappa, ct, ek) == 0 ? RLC_OK : RLC_ERR);
}

/** KEM: kappa <- ML-KEM.Decaps(dk, ct), with implicit rejection. */
static int kem_decaps(uint8_t *kappa, const uint8_t *ct, size_t ct_len,
		const uint8_t *dk) {
	if (ct_len != MLKEM_CT_LEN) {
		return RLC_ERR;
	}
	return (mlkem_decaps(kappa, ct, dk) == 0 ? RLC_OK : RLC_ERR);
}

/**
 * AEAD: AES-256-GCM under K. Each K encrypts a single message, so the nonce
 * is a fixed constant.
 */
static int ae_enc(uint8_t *e, size_t *e_len, const uint8_t *m, size_t m_len,
		const uint8_t *k) {
	static const uint8_t iv[12] = { 0 };

	*e_len = AE_MAX;
	return bc_aes_gcm_enc(e, e_len, m, m_len, k, LAM, iv, sizeof(iv), NULL, 0);
}

/** AEAD: AES-256-GCM decryption, which returns an error on an invalid tag. */
static int ae_dec(uint8_t *m, size_t *m_len, const uint8_t *e, size_t e_len,
		const uint8_t *k) {
	static const uint8_t iv[12] = { 0 };

	return bc_aes_gcm_dec(m, m_len, e, e_len, k, LAM, iv, sizeof(iv), NULL, 0);
}

/** Replaces a missing label by zeros, and rejects the zero label. */
static const uint8_t *label(const uint8_t *l) {
	static const uint8_t zero[LAM] = { 0 };
	uint8_t acc = 0;

	if (l == NULL) {
		return zero;
	}
	for (int j = 0; j < LAM; j++) {
		acc |= l[j];
	}
	return (acc == 0 ? NULL : l);
}

/** Times of the steps of one encryption or decryption, in milliseconds. */
static double t_own, t_other, t_rest;

/** T-PQ.Enc: Fig. 2 of the paper, steps 1 to 5. */
static int tpq_enc(tpq_ct_t *c, const tpq_pp_t *pp, const uint8_t *ek,
		const uint8_t *m, size_t m_len, const uint8_t *l) {
	bn_t u[2], chi[2];
	uint8_t kappa[LAM], k[LAM];
	double t0, t1, t2;
	int result = RLC_OK;

	if ((l = label(l)) == NULL || m_len > MSG_MAX) {
		return RLC_ERR;
	}
	for (int j = 0; j < 2; j++) {
		bn_null(u[j]);
		bn_null(chi[j]);
		bn_new(u[j]);
		bn_new(chi[j]);
	}

	/* 1: u <- Y_Dec, w = F_Dec.Bwd(u), a 1/eta fraction of theta. */
	t0 = now();
	bn_rand_mod(u[0], pp->p);
	bn_rand_mod(u[1], pp->p);
	result = cp_mroot_bwd(c->w[0], c->w[1], u[0], u[1], pp->theta, pp->p);
	t1 = now();
	/* 2: (kappa, ct) <- Encaps(ek), K = H2(u, kappa, l, ct). */
	if (result == RLC_OK) {
		result = kem_encaps(kappa, c->ct, &c->ct_len, ek);
	}
	if (result == RLC_OK) {
		h2(k, u[0], u[1], kappa, l, c->ct, c->ct_len);
		/* 3: e = AEAD.Enc(K, m). */
		result = ae_enc(c->e, &c->e_len, m, m_len, k);
	}
	t2 = now();
	/* 4: chi = H1(l, w, ct, e), y = F_Enc.Fwd(chi), tau rounds. */
	if (result == RLC_OK) {
		h1(chi[0], chi[1], l, c, pp->p);
		result = cp_mroot_fwd(c->y[0], c->y[1], chi[0], chi[1], pp->tau,
				pp->p);
	}
	t_other = t1 - t0;
	t_rest = t2 - t1;
	t_own = now() - t2;

	for (int j = 0; j < 2; j++) {
		bn_free(u[j]);
		bn_free(chi[j]);
	}
	return result;
}

/** T-PQ.Dec: Fig. 2 of the paper, steps 1 to 4. */
static int tpq_dec(uint8_t *m, size_t *m_len, const tpq_pp_t *pp,
		const uint8_t *dk, tpq_ct_t *c, const uint8_t *l) {
	bn_t u[2], chi[2], x[2];
	uint8_t kappa[LAM], k[LAM];
	double t0, t1, t2;
	int result = RLC_OK;

	if ((l = label(l)) == NULL) {
		return RLC_ERR;
	}
	for (int j = 0; j < 2; j++) {
		bn_null(u[j]);
		bn_null(chi[j]);
		bn_null(x[j]);
		bn_new(u[j]);
		bn_new(chi[j]);
		bn_new(x[j]);
	}

	/* 1: reject unless F_Enc.Bwd(y) = H1(l, w, ct, e), a 1/eta fraction of
	 * tau. */
	t0 = now();
	result = cp_mroot_bwd(x[0], x[1], c->y[0], c->y[1], pp->tau, pp->p);
	if (result == RLC_OK) {
		h1(chi[0], chi[1], l, c, pp->p);
		if (bn_cmp(x[0], chi[0]) != RLC_EQ || bn_cmp(x[1], chi[1]) != RLC_EQ) {
			result = RLC_ERR;
		}
	}
	t1 = now();
	/* 2: u = F_Dec.Fwd(w), theta rounds. */
	if (result == RLC_OK) {
		result = cp_mroot_fwd(u[0], u[1], c->w[0], c->w[1], pp->theta,
				pp->p);
	}
	t2 = now();
	/* 3: kappa = Decaps(dk, ct), K = H2(u, kappa, l, ct). */
	if (result == RLC_OK) {
		result = kem_decaps(kappa, c->ct, c->ct_len, dk);
	}
	/* 4: m = AEAD.Dec(K, e). */
	if (result == RLC_OK) {
		h2(k, u[0], u[1], kappa, l, c->ct, c->ct_len);
		result = ae_dec(m, m_len, c->e, c->e_len, k);
	}
	t_other = t1 - t0;
	t_own = t2 - t1;
	t_rest = now() - t2;

	for (int j = 0; j < 2; j++) {
		bn_free(u[j]);
		bn_free(chi[j]);
		bn_free(x[j]);
	}
	return result;
}

int main(int argc, char *argv[]) {
	tpq_pp_t pp;
	tpq_ct_t c;
	static uint8_t ek[MLKEM_EK_LEN], dk[MLKEM_DK_LEN];
	bn_t q;
	uint8_t l[LAM], m[MSG_MAX];
	const char *msg = "A message that took time to send and takes time to read";
	size_t m_len = sizeof(m);
	dig_t r;
	int code = 1;

	if (core_init() != RLC_OK) {
		core_clean();
		return 1;
	}

	pp.tau = (argc > 1 ? (size_t)atol(argv[1]) : 100);
	pp.theta = (argc > 2 ? (size_t)atol(argv[2]) : 100);
	bn_null(pp.p);
	bn_null(q);
	bn_new(pp.p);
	bn_new(q);
	for (int j = 0; j < 2; j++) {
		bn_null(c.y[j]);
		bn_null(c.w[j]);
		bn_new(c.y[j]);
		bn_new(c.w[j]);
	}

	/* Setup: one MinRoot family for both delays, with a transparent modulus
	 * whose conditions anyone can check. */
	bn_read_str(pp.p, MODP2048, strlen(MODP2048), 16);
	bn_sub_dig(q, pp.p, 1);
	bn_hlv(q, q);
	bn_mod_dig(&r, pp.p, 3);
	if (!bn_is_prime(pp.p) || !bn_is_prime(q) || r != 2) {
		printf("The MinRoot modulus is not a safe prime 2 mod 3.\n");
		goto end;
	}
	printf("T-PQ prototype with ML-KEM-1024 and AES-256-GCM\n");
	printf("MinRoot over a %d-bit safe prime, tau = %zu, theta = %zu\n\n",
			(int)bn_bits(pp.p), pp.tau, pp.theta);

	/* KeyGen. */
	if (mlkem_keygen(ek, dk) != 0) {
		goto end;
	}
	rand_bytes(l, LAM);
	l[0] |= 1;

	if (tpq_enc(&c, &pp, ek, (const uint8_t *)msg, strlen(msg), l) != RLC_OK) {
		printf("Encryption failed.\n");
		goto end;
	}
	printf("Enc: F_Enc.Fwd (tau rounds)     %10.2f ms\n", t_own);
	printf("     F_Dec.Bwd (theta / eta)    %10.2f ms\n", t_other);
	printf("     KEM, hashes and AEAD       %10.2f ms\n", t_rest);

	if (tpq_dec(m, &m_len, &pp, dk, &c, l) != RLC_OK ||
			m_len != strlen(msg) || memcmp(m, msg, m_len) != 0) {
		printf("Decryption failed.\n");
		goto end;
	}
	printf("Dec: F_Dec.Fwd (theta rounds)   %10.2f ms\n", t_own);
	printf("     F_Enc.Bwd (tau / eta)      %10.2f ms\n", t_other);
	printf("     KEM, hashes and AEAD       %10.2f ms\n", t_rest);
	printf("Decrypted: \"%.*s\"\n", (int)m_len, m);
	printf("Ciphertext: %d + %d + %zu + %zu bytes for y, w, ct and e\n\n",
			2 * FP_LEN, 2 * FP_LEN, c.ct_len, c.e_len);

	/* A ciphertext decrypts only under its own label, and any change to it
	 * is rejected. A wrong y fails the cheap check before the theta rounds. */
	l[LAM - 1] ^= 1;
	m_len = sizeof(m);
	printf("Wrong label rejected:           %s\n",
			tpq_dec(m, &m_len, &pp, dk, &c, l) == RLC_ERR ? "yes" : "NO");
	l[LAM - 1] ^= 1;
	c.e[0] ^= 1;
	m_len = sizeof(m);
	printf("Modified e rejected:            %s\n",
			tpq_dec(m, &m_len, &pp, dk, &c, l) == RLC_ERR ? "yes" : "NO");
	c.e[0] ^= 1;
	c.ct[0] ^= 1;
	m_len = sizeof(m);
	printf("Modified ct rejected:           %s\n",
			tpq_dec(m, &m_len, &pp, dk, &c, l) == RLC_ERR ? "yes" : "NO");
	c.ct[0] ^= 1;
	bn_add_dig(c.y[0], c.y[0], 1);
	bn_mod(c.y[0], c.y[0], pp.p);
	m_len = sizeof(m);
	printf("Modified y rejected:            %s (after %.2f ms)\n",
			tpq_dec(m, &m_len, &pp, dk, &c, l) == RLC_ERR ? "yes" : "NO",
			t_other);
	code = 0;

end:
	bn_free(pp.p);
	bn_free(q);
	for (int j = 0; j < 2; j++) {
		bn_free(c.y[j]);
		bn_free(c.w[j]);
	}
	core_clean();
	return code;
}
