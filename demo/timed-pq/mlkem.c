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
 * Compact implementation of ML-KEM-1024 from FIPS 203, following the
 * algorithms of the standard step by step. Coefficients are kept in [0, q)
 * and reduced with Barrett reduction, so that no secret value is divided.
 */

#include <string.h>

#include "relic.h"
#include "mlkem.h"

/** The modulus q. */
#define Q		3329

/** The degree of the polynomials. */
#define N		256

/** The module rank. */
#define K		MLKEM_K

/** Parameters of ML-KEM-1024. */
#define ETA1	2
#define ETA2	2
#define DU		11
#define DV		5

/** Rate of SHAKE128 in bytes. */
#define RATE	168

/** A polynomial, or its NTT representation, with coefficients in [0, q). */
typedef uint16_t poly_t[N];

/** Powers zeta^BitRev7(i) of the primitive 256-th root of unity zeta = 17. */
static uint16_t zetas[128];

/** Powers gamma_i = zeta^(2 BitRev7(i) + 1) for the base multiplication. */
static uint16_t gammas[128];

/** Computes floor(a / q) for a < 2^32, by Barrett reduction. */
static uint32_t q_div(uint32_t a) {
	uint32_t t = (uint32_t)(((uint64_t)a * 1290167) >> 32);
	uint32_t r = a - t * Q;
	/* The estimate is short by at most one, when r >= q. */
	return t + (1 ^ ((r - Q) >> 31));
}

/** Computes a mod q for a < 2^32. */
static uint16_t q_red(uint32_t a) {
	return (uint16_t)(a - q_div(a) * Q);
}

/** Computes a + b mod q for a, b in [0, q). */
static uint16_t q_add(uint16_t a, uint16_t b) {
	int32_t x = (int32_t)a + b - Q;
	return (uint16_t)(x + ((x >> 31) & Q));
}

/** Computes a - b mod q for a, b in [0, q). */
static uint16_t q_sub(uint16_t a, uint16_t b) {
	int32_t x = (int32_t)a - b;
	return (uint16_t)(x + ((x >> 31) & Q));
}

/** Fills the tables of powers of zeta, once. */
static void init(void) {
	static int ready = 0;

	if (ready) {
		return;
	}
	for (int i = 0; i < 128; i++) {
		int br = 0;
		uint16_t z = 1;
		for (int b = 0; b < 7; b++) {
			br |= ((i >> b) & 1) << (6 - b);
		}
		for (int j = 0; j < br; j++) {
			z = q_red((uint32_t)z * 17);
		}
		zetas[i] = z;
		gammas[i] = q_red((uint32_t)q_red((uint32_t)z * z) * 17);
	}
	ready = 1;
}

/** Algorithm 9: NTT. */
static void ntt(poly_t f) {
	int i = 1;

	for (int len = 128; len >= 2; len /= 2) {
		for (int start = 0; start < N; start += 2 * len) {
			uint16_t z = zetas[i++];
			for (int j = start; j < start + len; j++) {
				uint16_t t = q_red((uint32_t)z * f[j + len]);
				f[j + len] = q_sub(f[j], t);
				f[j] = q_add(f[j], t);
			}
		}
	}
}

/** Algorithm 10: NTT^(-1), including the final scaling by 128^(-1). */
static void ntt_inv(poly_t f) {
	int i = 127;

	for (int len = 2; len <= 128; len *= 2) {
		for (int start = 0; start < N; start += 2 * len) {
			uint16_t z = zetas[i--];
			for (int j = start; j < start + len; j++) {
				uint16_t t = f[j];
				f[j] = q_add(t, f[j + len]);
				f[j + len] = q_red((uint32_t)z * q_sub(f[j + len], t));
			}
		}
	}
	for (int j = 0; j < N; j++) {
		f[j] = q_red((uint32_t)f[j] * 3303);
	}
}

/** Algorithms 11 and 12: accumulates h += f * g in the NTT domain. */
static void mul_acc(poly_t h, const poly_t f, const poly_t g) {
	for (int i = 0; i < 128; i++) {
		uint32_t a0 = f[2 * i], a1 = f[2 * i + 1];
		uint32_t b0 = g[2 * i], b1 = g[2 * i + 1];
		uint16_t c0 = q_red(a0 * b0 + (uint32_t)q_red(a1 * b1) * gammas[i]);
		uint16_t c1 = q_red(a0 * b1 + a1 * b0);
		h[2 * i] = q_add(h[2 * i], c0);
		h[2 * i + 1] = q_add(h[2 * i + 1], c1);
	}
}

/** Algorithm 5: ByteEncode_d, packing 256 d-bit integers little-endian. */
static void encode(uint8_t *out, const poly_t f, int d) {
	uint32_t acc = 0;
	int bits = 0;

	for (int i = 0; i < N; i++) {
		acc |= (uint32_t)f[i] << bits;
		bits += d;
		while (bits >= 8) {
			*out++ = (uint8_t)acc;
			acc >>= 8;
			bits -= 8;
		}
	}
}

/** Algorithm 6: ByteDecode_d, without the reduction for d = 12. */
static void decode(poly_t f, const uint8_t *in, int d) {
	uint32_t acc = 0;
	int bits = 0;

	for (int i = 0; i < N; i++) {
		while (bits < d) {
			acc |= (uint32_t)*in++ << bits;
			bits += 8;
		}
		f[i] = (uint16_t)(acc & ((1u << d) - 1));
		acc >>= d;
		bits -= d;
	}
}

/** Compress_d: round(2^d x / q) mod 2^d, applied to a polynomial. */
static void compress(poly_t f, int d) {
	for (int i = 0; i < N; i++) {
		f[i] = (uint16_t)(q_div(((uint32_t)f[i] << d) + Q / 2) &
				((1u << d) - 1));
	}
}

/** Decompress_d: round(q y / 2^d), applied to a polynomial. */
static void decompress(poly_t f, int d) {
	for (int i = 0; i < N; i++) {
		f[i] = (uint16_t)(((uint32_t)f[i] * Q + (1u << (d - 1))) >> d);
	}
}

/** Algorithm 7: SampleNTT, rejection sampling from SHAKE128(rho | j | i). */
static int sample_ntt(poly_t f, const uint8_t *rho, uint8_t j, uint8_t i) {
	uint8_t in[34], buf[16 * RATE];
	size_t len = 3 * RATE;

	memcpy(in, rho, 32);
	in[32] = j;
	in[33] = i;
	/* A longer output of SHAKE128 extends a shorter one, so sampling can
	 * restart over more blocks in the rare case it runs short. */
	while (len <= sizeof(buf)) {
		int n = 0;
		md_shake128(buf, len, in, sizeof(in));
		for (size_t p = 0; p + 3 <= len && n < N; p += 3) {
			uint16_t d1 = buf[p] | ((uint16_t)(buf[p + 1] & 0x0F) << 8);
			uint16_t d2 = (buf[p + 1] >> 4) | ((uint16_t)buf[p + 2] << 4);
			if (d1 < Q) {
				f[n++] = d1;
			}
			if (d2 < Q && n < N) {
				f[n++] = d2;
			}
		}
		if (n == N) {
			return 0;
		}
		len += RATE;
	}
	return -1;
}

/** Algorithm 8: SamplePolyCBD_eta from PRF_eta(s, b) = SHAKE256(s | b). */
static void sample_cbd(poly_t f, const uint8_t *s, uint8_t b, int eta) {
	uint8_t in[33], buf[64 * 3];

	memcpy(in, s, 32);
	in[32] = b;
	md_shake256(buf, 64 * eta, in, sizeof(in));
	for (int i = 0; i < N; i++) {
		uint16_t x = 0, y = 0;
		for (int j = 0; j < eta; j++) {
			int p = 2 * i * eta + j;
			x += (buf[p / 8] >> (p % 8)) & 1;
			p += eta;
			y += (buf[p / 8] >> (p % 8)) & 1;
		}
		f[i] = q_sub(x, y);
	}
}

/** Samples the matrix A, with A[i][j] = SampleNTT(rho | j | i). */
static int sample_matrix(poly_t a[K][K], const uint8_t *rho) {
	for (int i = 0; i < K; i++) {
		for (int j = 0; j < K; j++) {
			if (sample_ntt(a[i][j], rho, (uint8_t)j, (uint8_t)i) != 0) {
				return -1;
			}
		}
	}
	return 0;
}

/** Algorithm 13: K-PKE.KeyGen. */
static int kpke_keygen(uint8_t *ek, uint8_t *dk, const uint8_t *d) {
	poly_t a[K][K], s[K], e[K], t;
	uint8_t g[33], rs[64];
	uint8_t n = 0;

	/* (rho, sigma) = G(d | k). */
	memcpy(g, d, 32);
	g[32] = K;
	md_map_s3512(rs, g, sizeof(g));
	if (sample_matrix(a, rs) != 0) {
		return -1;
	}
	for (int i = 0; i < K; i++) {
		sample_cbd(s[i], rs + 32, n++, ETA1);
	}
	for (int i = 0; i < K; i++) {
		sample_cbd(e[i], rs + 32, n++, ETA1);
	}
	for (int i = 0; i < K; i++) {
		ntt(s[i]);
		ntt(e[i]);
	}
	/* t = A s + e in the NTT domain. */
	for (int i = 0; i < K; i++) {
		memcpy(t, e[i], sizeof(poly_t));
		for (int j = 0; j < K; j++) {
			mul_acc(t, a[i][j], s[j]);
		}
		encode(ek + 384 * i, t, 12);
		encode(dk + 384 * i, s[i], 12);
	}
	memcpy(ek + 384 * K, rs, 32);
	memset(s, 0, sizeof(s));
	memset(rs, 0, sizeof(rs));
	return 0;
}

/** Algorithm 14: K-PKE.Encrypt. */
static int kpke_enc(uint8_t *c, const uint8_t *ek, const uint8_t *m,
		const uint8_t *r) {
	poly_t a[K][K], t[K], y[K], u, v, f;
	uint8_t n = 0;

	for (int i = 0; i < K; i++) {
		decode(t[i], ek + 384 * i, 12);
	}
	if (sample_matrix(a, ek + 384 * K) != 0) {
		return -1;
	}
	for (int i = 0; i < K; i++) {
		sample_cbd(y[i], r, n++, ETA1);
		ntt(y[i]);
	}
	/* u = NTT^(-1)(A^T y) + e1, compressed to du bits. */
	for (int i = 0; i < K; i++) {
		memset(u, 0, sizeof(u));
		for (int j = 0; j < K; j++) {
			mul_acc(u, a[j][i], y[j]);
		}
		ntt_inv(u);
		sample_cbd(f, r, n++, ETA2);
		for (int k = 0; k < N; k++) {
			u[k] = q_add(u[k], f[k]);
		}
		compress(u, DU);
		encode(c + 32 * DU * i, u, DU);
	}
	/* v = NTT^(-1)(t^T y) + e2 + Decompress_1(m), compressed to dv bits. */
	memset(v, 0, sizeof(v));
	for (int j = 0; j < K; j++) {
		mul_acc(v, t[j], y[j]);
	}
	ntt_inv(v);
	sample_cbd(f, r, n++, ETA2);
	for (int k = 0; k < N; k++) {
		uint16_t mu = (uint16_t)(-(uint16_t)((m[k / 8] >> (k % 8)) & 1) &
				((Q + 1) / 2));
		v[k] = q_add(q_add(v[k], f[k]), mu);
	}
	compress(v, DV);
	encode(c + 32 * DU * K, v, DV);
	memset(y, 0, sizeof(y));
	return 0;
}

/** Algorithm 15: K-PKE.Decrypt. */
static void kpke_dec(uint8_t *m, const uint8_t *dk, const uint8_t *c) {
	poly_t s, u, v, w;

	memset(w, 0, sizeof(w));
	for (int i = 0; i < K; i++) {
		decode(u, c + 32 * DU * i, DU);
		decompress(u, DU);
		ntt(u);
		decode(s, dk + 384 * i, 12);
		mul_acc(w, s, u);
	}
	ntt_inv(w);
	decode(v, c + 32 * DU * K, DV);
	decompress(v, DV);
	/* m = Compress_1(v - NTT^(-1)(s^T u)). */
	for (int k = 0; k < N; k++) {
		w[k] = q_sub(v[k], w[k]);
	}
	compress(w, 1);
	encode(m, w, 1);
	memset(s, 0, sizeof(s));
	memset(w, 0, sizeof(w));
}

int mlkem_keygen_seed(uint8_t *ek, uint8_t *dk, const uint8_t *d,
		const uint8_t *z) {
	init();
	/* dk = dk_PKE | ek | H(ek) | z. */
	if (kpke_keygen(ek, dk, d) != 0) {
		return -1;
	}
	memcpy(dk + 384 * K, ek, MLKEM_EK_LEN);
	md_map_s3256(dk + 384 * K + MLKEM_EK_LEN, ek, MLKEM_EK_LEN);
	memcpy(dk + 384 * K + MLKEM_EK_LEN + 32, z, 32);
	return 0;
}

int mlkem_keygen(uint8_t *ek, uint8_t *dk) {
	uint8_t d[32], z[32];
	int result;

	rand_bytes(d, sizeof(d));
	rand_bytes(z, sizeof(z));
	result = mlkem_keygen_seed(ek, dk, d, z);
	memset(d, 0, sizeof(d));
	return result;
}

int mlkem_encaps(uint8_t *ss, uint8_t *ct, const uint8_t *ek) {
	poly_t t;
	uint8_t g[64], kr[64];
	int result;

	init();
	/* Modulus check: every coefficient of the key is below q. */
	for (int i = 0; i < K; i++) {
		decode(t, ek + 384 * i, 12);
		for (int k = 0; k < N; k++) {
			if (t[k] >= Q) {
				return -1;
			}
		}
	}
	/* (K, r) = G(m | H(ek)). */
	rand_bytes(g, 32);
	md_map_s3256(g + 32, ek, MLKEM_EK_LEN);
	md_map_s3512(kr, g, sizeof(g));
	result = kpke_enc(ct, ek, g, kr + 32);
	if (result == 0) {
		memcpy(ss, kr, MLKEM_SS_LEN);
	}
	memset(g, 0, sizeof(g));
	memset(kr, 0, sizeof(kr));
	return result;
}

int mlkem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *dk) {
	const uint8_t *ek = dk + 384 * K, *h = ek + MLKEM_EK_LEN, *z = h + 32;
	uint8_t g[64], kr[64], rej[32], h2[32], c2[MLKEM_CT_LEN], zc[32 +
			MLKEM_CT_LEN], diff = 0, mask;

	init();
	/* Hash check: the copy of ek in dk matches its hash. */
	md_map_s3256(h2, ek, MLKEM_EK_LEN);
	if (memcmp(h2, h, 32) != 0) {
		return -1;
	}
	/* m' = Decrypt(dk_PKE, c) and (K', r') = G(m' | h). */
	kpke_dec(g, dk, ct);
	memcpy(g + 32, h, 32);
	md_map_s3512(kr, g, sizeof(g));
	/* The rejection key is J(z | c) = SHAKE256(z | c). */
	memcpy(zc, z, 32);
	memcpy(zc + 32, ct, MLKEM_CT_LEN);
	md_shake256(rej, sizeof(rej), zc, sizeof(zc));
	/* Re-encrypt and select K' or the rejection key in constant time. */
	if (kpke_enc(c2, ek, g, kr + 32) != 0) {
		return -1;
	}
	for (int i = 0; i < MLKEM_CT_LEN; i++) {
		diff |= c2[i] ^ ct[i];
	}
	mask = (uint8_t)(-(uint8_t)((uint32_t)(diff - 1) >> 31 & 1));
	for (int i = 0; i < MLKEM_SS_LEN; i++) {
		ss[i] = (kr[i] & mask) | (rej[i] & ~mask);
	}
	memset(g, 0, sizeof(g));
	memset(kr, 0, sizeof(kr));
	return 0;
}
