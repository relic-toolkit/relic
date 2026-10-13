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
 * Implementation of the RSA cryptosystem.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Length of the minimum padding of the chosen scheme in bytes.
 */
#if CP_RSAPD == PKCS1
#define RSA_PAD_LEN		(11)
#elif CP_RSAPD == PKCS2
#define RSA_PAD_LEN		(2 * RLC_MD_LEN + 2)
#else
#define RSA_PAD_LEN		(2)
#endif

/**
 * Returns 1 if a byte is zero and 0 otherwise, in constant time.
 */
#define RSA_IS_ZERO(B)		((uint32_t)((uint32_t)(B) - 1) >> 31)

/**
 * Computes the private-key operation c = a^d mod n. The input is blinded with
 * r^e for a random r, and the result is checked against faults before the
 * blinding is removed.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the input, in [0, n).
 * @param[in] prv			- the private key, including the public exponent.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int rsa_exp_prv(bn_t c, const bn_t a, const rsa_t prv) {
	bn_t r, s, t, u;
	int result = RLC_OK;

	if (bn_is_zero(prv->e)) {
		return RLC_ERR;
	}

	bn_null_all(r, s, t, u);

	RLC_TRY {
		bn_new_all(r, s, t, u);

		/* t = a * r^e mod n. */
		bn_rand_mod(r, prv->crt->n);
		bn_mxp(t, r, prv->e, prv->crt->n);
		bn_mul(t, t, a);
		bn_mod(t, t, prv->crt->n);

		/* s = t^d mod n. */
#if !defined(CP_CRT)
		bn_mxp(s, t, prv->d, prv->crt->n);
#else
		bn_mxp_crt(s, t, prv->crt->dp, prv->crt->dq, prv->crt, 0);
#endif

		/* A fault in either half of the CRT would reveal a factor of n. */
		bn_mxp(u, s, prv->e, prv->crt->n);
		if (bn_cmp(u, t) != RLC_EQ) {
			result = RLC_ERR;
		} else {
			/* c = s / r mod n. */
			bn_mod_inv(r, r, prv->crt->n);
			bn_mul(s, s, r);
			bn_mod(c, s, prv->crt->n);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free_all(r, s, t, u);
	}
	return result;
}

#if CP_RSAPD == BASIC

/**
 * Encodes a message as EM = 00 | ... | 00 | FF | M.
 *
 * @param[out] em			- the encoded message.
 * @param[in] k				- the length of the encoded message in bytes.
 * @param[in] m				- the message.
 * @param[in] m_len			- the message length in bytes, at most k - 2.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_enc(uint8_t *em, size_t k, const uint8_t *m, size_t m_len) {
	memset(em, 0, k - m_len - 1);
	em[k - m_len - 1] = 0xFF;
	memcpy(em + k - m_len, m, m_len);
	return RLC_OK;
}

/**
 * Decodes a message encoded as EM = 00 | ... | 00 | FF | M, in constant time
 * up to the result.
 *
 * @param[out] m			- the message.
 * @param[in,out] m_len		- the buffer capacity and the message length.
 * @param[in] em			- the encoded message.
 * @param[in] k				- the length of the encoded message in bytes.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_dec(uint8_t *m, size_t *m_len, uint8_t *em, size_t k) {
	uint32_t good, found = 0, nz, sel, b = 0;
	size_t idx = 0;

	good = RSA_IS_ZERO(em[0]);
	for (size_t i = 1; i < k; i++) {
		nz = RSA_IS_ZERO(em[i]) ^ 1;
		sel = nz & (found ^ 1);
		idx = RLC_SEL(idx, i, (size_t)sel);
		b = RLC_SEL(b, em[i], sel);
		found |= nz;
	}
	good &= found & RSA_IS_ZERO(b ^ 0xFF);

	if (!good || k - idx - 1 > *m_len) {
		return RLC_ERR;
	}
	*m_len = k - idx - 1;
	memcpy(m, em + idx + 1, *m_len);
	return RLC_OK;
}

/**
 * Encodes a digest for signing as EM = 00 | ... | 00 | FF | H.
 *
 * @param[out] em			- the encoded message.
 * @param[in] em_bits		- the length of the encoded message in bits.
 * @param[in] h				- the digest.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_sig(uint8_t *em, size_t em_bits, const uint8_t *h) {
	if (RLC_CEIL(em_bits, 8) < RLC_MD_LEN + RSA_PAD_LEN) {
		return RLC_ERR;
	}
	return pad_enc(em, RLC_CEIL(em_bits, 8), h, RLC_MD_LEN);
}

#endif

#if CP_RSAPD == PKCS1

/**
 * ASN.1 identifier of the hash function SHA-224.
 */
static const uint8_t sh224_id[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c
};

/**
 * ASN.1 identifier of the hash function SHA-256.
 */
static const uint8_t sh256_id[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

/**
 * ASN.1 identifier of the hash function SHA-384.
 */
static const uint8_t sh384_id[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};

/**
 * ASN.1 identifier of the hash function SHA-512.
 */
static const uint8_t sh512_id[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
	0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

/**
 * Returns the ASN.1 DigestInfo prefix of the chosen hash function, as in the
 * PKCS#1 v1.5 signature encoding.
 *
 * @param[out] len			- the length of the prefix.
 * @return the prefix, or NULL if the hash function has none.
 */
static const uint8_t *hash_id(size_t *len) {
	switch (MD_MAP) {
		case SH224:
			*len = sizeof(sh224_id);
			return sh224_id;
		case SH256:
			*len = sizeof(sh256_id);
			return sh256_id;
		case SH384:
			*len = sizeof(sh384_id);
			return sh384_id;
		case SH512:
			*len = sizeof(sh512_id);
			return sh512_id;
		default:
			*len = 0;
			return NULL;
	}
}

/**
 * Encodes a message for encryption with EME-PKCS1-v1_5:
 * EM = 00 | 02 | PS | 00 | M, with PS made of at least 8 nonzero random bytes.
 *
 * @param[out] em			- the encoded message.
 * @param[in] k				- the length of the encoded message in bytes.
 * @param[in] m				- the message.
 * @param[in] m_len			- the message length in bytes, at most k - 11.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_enc(uint8_t *em, size_t k, const uint8_t *m, size_t m_len) {
	size_t ps_len = k - m_len - 3;

	em[0] = 0x00;
	em[1] = 0x02;
	rand_bytes(em + 2, ps_len);
	for (size_t i = 0; i < ps_len; i++) {
		while (em[i + 2] == 0) {
			rand_bytes(em + i + 2, 1);
		}
	}
	em[ps_len + 2] = 0x00;
	memcpy(em + ps_len + 3, m, m_len);
	return RLC_OK;
}

/**
 * Decodes a message encoded with EME-PKCS1-v1_5, in constant time up to the
 * result.
 *
 * @param[out] m			- the message.
 * @param[in,out] m_len		- the buffer capacity and the message length.
 * @param[in] em			- the encoded message.
 * @param[in] k				- the length of the encoded message in bytes.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_dec(uint8_t *m, size_t *m_len, uint8_t *em, size_t k) {
	uint32_t good, found = 0, zero, sel;
	size_t idx = 0;

	good = RSA_IS_ZERO(em[0]) & RSA_IS_ZERO(em[1] ^ 0x02);
	for (size_t i = 2; i < k; i++) {
		zero = RSA_IS_ZERO(em[i]);
		sel = zero & (found ^ 1);
		idx = RLC_SEL(idx, i, (size_t)sel);
		found |= zero;
	}
	/* The separator must come after at least 8 bytes of padding. */
	good &= found & (uint32_t)(((uint64_t)9 - idx) >> 63);

	if (!good || k - idx - 1 > *m_len) {
		return RLC_ERR;
	}
	*m_len = k - idx - 1;
	memcpy(m, em + idx + 1, *m_len);
	return RLC_OK;
}

/**
 * Encodes a digest for signing with EMSA-PKCS1-v1_5:
 * EM = 00 | 01 | FF | ... | FF | 00 | DigestInfo | H.
 *
 * @param[out] em			- the encoded message.
 * @param[in] em_bits		- the length of the encoded message in bits.
 * @param[in] h				- the digest.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_sig(uint8_t *em, size_t em_bits, const uint8_t *h) {
	size_t k = RLC_CEIL(em_bits, 8), id_len, ps_len;
	const uint8_t *id = hash_id(&id_len);

	if (id == NULL || id_len + RLC_MD_LEN + RSA_PAD_LEN > k) {
		return RLC_ERR;
	}
	ps_len = k - id_len - RLC_MD_LEN - 3;
	em[0] = 0x00;
	em[1] = 0x01;
	memset(em + 2, 0xFF, ps_len);
	em[ps_len + 2] = 0x00;
	memcpy(em + ps_len + 3, id, id_len);
	memcpy(em + ps_len + 3 + id_len, h, RLC_MD_LEN);
	return RLC_OK;
}

#endif

#if CP_RSAPD == BASIC || CP_RSAPD == PKCS1

/**
 * Verifies an encoded signature by encoding the digest again and comparing.
 *
 * @param[in] em			- the encoded message.
 * @param[in] em_bits		- the length of the encoded message in bits.
 * @param[in] h				- the digest.
 * @return 1 if the encoding is valid, 0 otherwise.
 */
static int pad_ver(const uint8_t *em, size_t em_bits, const uint8_t *h) {
	size_t k = RLC_CEIL(em_bits, 8);
	uint8_t *t = RLC_ALLOCA(uint8_t, k);
	int result = 0;

	if (t == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}
	if (pad_sig(t, em_bits, h) == RLC_OK) {
		result = (util_cmp_sec(t, em, k) == RLC_EQ);
	}
	RLC_FREE(t);
	return result;
}

#endif

#if CP_RSAPD == PKCS2

/**
 * Encodes a message for encryption with EME-OAEP and an empty label:
 * EM = 00 | maskedSeed | maskedDB, with DB = lHash | PS | 01 | M.
 *
 * @param[out] em			- the encoded message.
 * @param[in] k				- the length of the encoded message in bytes.
 * @param[in] m				- the message.
 * @param[in] m_len			- the message length in bytes, at most
 * 							  k - 2 * RLC_MD_LEN - 2.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_enc(uint8_t *em, size_t k, const uint8_t *m, size_t m_len) {
	size_t db_len = k - RLC_MD_LEN - 1;
	uint8_t *seed = em + 1, *db = em + 1 + RLC_MD_LEN;
	uint8_t *mask = RLC_ALLOCA(uint8_t, db_len);

	if (mask == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	em[0] = 0x00;
	md_map(db, NULL, 0);
	memset(db + RLC_MD_LEN, 0, db_len - m_len - RLC_MD_LEN - 1);
	db[db_len - m_len - 1] = 0x01;
	memcpy(db + db_len - m_len, m, m_len);

	rand_bytes(seed, RLC_MD_LEN);
	md_mgf(mask, db_len, seed, RLC_MD_LEN);
	for (size_t i = 0; i < db_len; i++) {
		db[i] ^= mask[i];
	}
	md_mgf(mask, RLC_MD_LEN, db, db_len);
	for (size_t i = 0; i < RLC_MD_LEN; i++) {
		seed[i] ^= mask[i];
	}

	RLC_FREE(mask);
	return RLC_OK;
}

/**
 * Decodes a message encoded with EME-OAEP and an empty label, in constant time
 * up to the result. The encoded message is unmasked in place.
 *
 * @param[out] m			- the message.
 * @param[in,out] m_len		- the buffer capacity and the message length.
 * @param[in,out] em		- the encoded message.
 * @param[in] k				- the length of the encoded message in bytes.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_dec(uint8_t *m, size_t *m_len, uint8_t *em, size_t k) {
	size_t db_len = k - RLC_MD_LEN - 1, idx = 0;
	uint8_t *seed = em + 1, *db = em + 1 + RLC_MD_LEN, h[RLC_MD_LEN], diff = 0;
	uint8_t *mask = RLC_ALLOCA(uint8_t, db_len);
	uint32_t good, found = 0, bad = 0, one, zero, sel;

	if (mask == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	md_mgf(mask, RLC_MD_LEN, db, db_len);
	for (size_t i = 0; i < RLC_MD_LEN; i++) {
		seed[i] ^= mask[i];
	}
	md_mgf(mask, db_len, seed, RLC_MD_LEN);
	for (size_t i = 0; i < db_len; i++) {
		db[i] ^= mask[i];
	}
	RLC_FREE(mask);

	md_map(h, NULL, 0);
	for (size_t i = 0; i < RLC_MD_LEN; i++) {
		diff |= db[i] ^ h[i];
	}
	good = RSA_IS_ZERO(em[0]) & RSA_IS_ZERO(diff);

	/* Find the 01 separator, rejecting any other nonzero byte before it. */
	for (size_t i = RLC_MD_LEN; i < db_len; i++) {
		one = RSA_IS_ZERO(db[i] ^ 0x01);
		zero = RSA_IS_ZERO(db[i]);
		sel = one & (found ^ 1);
		idx = RLC_SEL(idx, i, (size_t)sel);
		bad |= (found ^ 1) & (zero ^ 1) & (one ^ 1);
		found |= one;
	}
	good &= found & (bad ^ 1);

	if (!good || db_len - idx - 1 > *m_len) {
		return RLC_ERR;
	}
	*m_len = db_len - idx - 1;
	memcpy(m, db + idx + 1, *m_len);
	return RLC_OK;
}

/**
 * Encodes a digest for signing with EMSA-PSS and a salt as long as the digest:
 * EM = maskedDB | H | BC, with H = Hash(0^64 | mHash | salt) and
 * DB = PS | 01 | salt.
 *
 * @param[out] em			- the encoded message.
 * @param[in] em_bits		- the length of the encoded message in bits.
 * @param[in] h				- the digest.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int pad_sig(uint8_t *em, size_t em_bits, const uint8_t *h) {
	size_t em_len = RLC_CEIL(em_bits, 8), db_len;
	uint8_t *db = em, *hh, *mask, buf[8 + 2 * RLC_MD_LEN];
	uint8_t *salt = buf + 8 + RLC_MD_LEN;

	if (em_len < 2 * RLC_MD_LEN + 2) {
		return RLC_ERR;
	}
	db_len = em_len - RLC_MD_LEN - 1;
	hh = em + db_len;
	mask = RLC_ALLOCA(uint8_t, db_len);
	if (mask == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	memset(buf, 0, 8);
	memcpy(buf + 8, h, RLC_MD_LEN);
	rand_bytes(salt, RLC_MD_LEN);
	md_map(hh, buf, sizeof(buf));

	memset(db, 0, db_len - RLC_MD_LEN - 1);
	db[db_len - RLC_MD_LEN - 1] = 0x01;
	memcpy(db + db_len - RLC_MD_LEN, salt, RLC_MD_LEN);
	md_mgf(mask, db_len, hh, RLC_MD_LEN);
	for (size_t i = 0; i < db_len; i++) {
		db[i] ^= mask[i];
	}
	db[0] &= 0xFF >> (8 * em_len - em_bits);
	em[em_len - 1] = 0xBC;

	RLC_FREE(mask);
	return RLC_OK;
}

/**
 * Verifies a digest against a message encoded with EMSA-PSS and a salt as long
 * as the digest. The encoded message is unmasked in place.
 *
 * @param[in,out] em		- the encoded message.
 * @param[in] em_bits		- the length of the encoded message in bits.
 * @param[in] h				- the digest.
 * @return 1 if the encoding is valid, 0 otherwise.
 */
static int pad_ver(uint8_t *em, size_t em_bits, const uint8_t *h) {
	size_t em_len = RLC_CEIL(em_bits, 8), db_len;
	uint8_t *db = em, *hh, *mask, buf[8 + 2 * RLC_MD_LEN];
	uint8_t top = 0xFF >> (8 * em_len - em_bits), h2[RLC_MD_LEN];
	int result = 1;

	if (em_len < 2 * RLC_MD_LEN + 2 || em[em_len - 1] != 0xBC ||
			(db[0] & ~top) != 0) {
		return 0;
	}
	db_len = em_len - RLC_MD_LEN - 1;
	hh = em + db_len;
	mask = RLC_ALLOCA(uint8_t, db_len);
	if (mask == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	md_mgf(mask, db_len, hh, RLC_MD_LEN);
	for (size_t i = 0; i < db_len; i++) {
		db[i] ^= mask[i];
	}
	RLC_FREE(mask);
	db[0] &= top;

	for (size_t i = 0; i < db_len - RLC_MD_LEN - 1; i++) {
		if (db[i] != 0) {
			result = 0;
		}
	}
	if (db[db_len - RLC_MD_LEN - 1] != 0x01) {
		result = 0;
	}

	memset(buf, 0, 8);
	memcpy(buf + 8, h, RLC_MD_LEN);
	memcpy(buf + 8 + RLC_MD_LEN, db + db_len - RLC_MD_LEN, RLC_MD_LEN);
	md_map(h2, buf, sizeof(buf));
	if (util_cmp_sec(h2, hh, RLC_MD_LEN) != RLC_EQ) {
		result = 0;
	}
	return result;
}

#endif

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_rsa_gen(rsa_t pub, rsa_t prv, size_t bits) {
	bn_t t, r;
	int result = RLC_OK;

	if (pub == NULL || prv == NULL || bits < 16) {
		return RLC_ERR;
	}

	bn_null(t);
	bn_null(r);

	RLC_TRY {
		bn_new(t);
		bn_new(r);

		bn_set_2b(pub->e, 16);
		bn_add_dig(pub->e, pub->e, 1);
		bn_copy(prv->e, pub->e);

		do {
			/* Generate different primes p and q with n = pq of exactly the
			 * requested length. */
			do {
				bn_gen_prime(prv->crt->p, bits / 2);
				bn_gen_prime(prv->crt->q, bits - bits / 2);
				bn_mul(pub->crt->n, prv->crt->p, prv->crt->q);
			} while (bn_cmp(prv->crt->p, prv->crt->q) == RLC_EQ ||
					bn_bits(pub->crt->n) != bits);

			/* phi(n) = (p - 1)(q - 1). */
			bn_sub_dig(t, prv->crt->p, 1);
			bn_sub_dig(r, prv->crt->q, 1);
			bn_mul(t, t, r);

			/* d = e^(-1) mod phi(n), which needs gcd(e, phi(n)) = 1. */
			bn_gcd_ext(r, prv->d, NULL, pub->e, t);
		} while (bn_cmp_dig(r, 1) != RLC_EQ);

		if (bn_sign(prv->d) == RLC_NEG) {
			bn_add(prv->d, prv->d, t);
		}

		/* Swap p and q so that p is smaller. */
		if (bn_cmp(prv->crt->p, prv->crt->q) != RLC_LT) {
			bn_copy(t, prv->crt->p);
			bn_copy(prv->crt->p, prv->crt->q);
			bn_copy(prv->crt->q, t);
		}
		bn_copy(prv->crt->n, pub->crt->n);

#if defined(CP_CRT)
		/* dP = d mod (p - 1). */
		bn_sub_dig(t, prv->crt->p, 1);
		bn_mod(prv->crt->dp, prv->d, t);
		/* dQ = d mod (q - 1). */
		bn_sub_dig(t, prv->crt->q, 1);
		bn_mod(prv->crt->dq, prv->d, t);
		/* qInv = q^(-1) mod p. */
		bn_mod_inv(prv->crt->qi, prv->crt->q, prv->crt->p);
#endif /* CP_CRT */
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(r);
	}

	return result;
}

int cp_rsa_enc(uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len,
		const rsa_t pub) {
	bn_t m;
	size_t k;
	uint8_t *em;
	int result = RLC_OK;

	if (pub == NULL) {
		return RLC_ERR;
	}

	k = bn_size_bin(pub->crt->n);
	if (in_len + RSA_PAD_LEN > k || *out_len < k) {
		return RLC_ERR;
	}

	em = RLC_ALLOCA(uint8_t, k);
	if (em == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(m);

	RLC_TRY {
		bn_new(m);

		if (pad_enc(em, k, in, in_len) == RLC_OK) {
			bn_read_bin(m, em, k);
			bn_mxp(m, m, pub->e, pub->crt->n);
			bn_write_bin(out, k, m);
			*out_len = k;
		} else {
			result = RLC_ERR;
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		RLC_FREE(em);
	}

	return result;
}

int cp_rsa_dec(uint8_t *out, size_t *out_len, const uint8_t *in, size_t in_len,
		const rsa_t prv) {
	bn_t m;
	size_t k;
	uint8_t *em;
	int result = RLC_OK;

	if (prv == NULL) {
		return RLC_ERR;
	}

	k = bn_size_bin(prv->crt->n);
	if (in_len != k || k < RSA_PAD_LEN) {
		return RLC_ERR;
	}

	em = RLC_ALLOCA(uint8_t, k);
	if (em == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(m);

	RLC_TRY {
		bn_new(m);

		bn_read_bin(m, in, in_len);
		if (bn_cmp(m, prv->crt->n) != RLC_LT ||
				rsa_exp_prv(m, m, prv) != RLC_OK) {
			result = RLC_ERR;
		} else {
			bn_write_bin(em, k, m);
			result = pad_dec(out, out_len, em, k);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		RLC_FREE(em);
	}

	return result;
}

int cp_rsa_sig(uint8_t *sig, size_t *sig_len, const uint8_t *msg,
		size_t msg_len, int hash, const rsa_t prv) {
	bn_t m;
	size_t k, em_bits;
	uint8_t h[RLC_MD_LEN], *em;
	int result = RLC_OK;

	if (prv == NULL || (hash && msg_len != RLC_MD_LEN)) {
		return RLC_ERR;
	}

	k = bn_size_bin(prv->crt->n);
#if CP_RSAPD == PKCS2
	/* The encoded message has the bit length of the modulus minus one. */
	em_bits = bn_bits(prv->crt->n) - 1;
#else
	em_bits = 8 * k;
#endif
	if (k < RSA_PAD_LEN || *sig_len < k) {
		return RLC_ERR;
	}

	em = RLC_ALLOCA(uint8_t, RLC_CEIL(em_bits, 8));
	if (em == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(m);

	RLC_TRY {
		bn_new(m);

		if (hash) {
			memcpy(h, msg, RLC_MD_LEN);
		} else {
			md_map(h, msg, msg_len);
		}

		if (pad_sig(em, em_bits, h) == RLC_OK) {
			bn_read_bin(m, em, RLC_CEIL(em_bits, 8));
			if (rsa_exp_prv(m, m, prv) == RLC_OK) {
				bn_write_bin(sig, k, m);
				*sig_len = k;
			} else {
				result = RLC_ERR;
			}
		} else {
			result = RLC_ERR;
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(m);
		RLC_FREE(em);
	}

	return result;
}

int cp_rsa_ver(const uint8_t *sig, size_t sig_len, const uint8_t *msg,
		size_t msg_len, int hash, const rsa_t pub) {
	bn_t m;
	size_t k, em_bits;
	uint8_t h[RLC_MD_LEN], *em;
	int result = 0;

	if (pub == NULL || (hash && msg_len != RLC_MD_LEN)) {
		return 0;
	}

	k = bn_size_bin(pub->crt->n);
#if CP_RSAPD == PKCS2
	/* The encoded message has the bit length of the modulus minus one. */
	em_bits = bn_bits(pub->crt->n) - 1;
#else
	em_bits = 8 * k;
#endif
	if (sig_len != k || k < RSA_PAD_LEN) {
		return 0;
	}

	em = RLC_ALLOCA(uint8_t, RLC_CEIL(em_bits, 8));
	if (em == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	bn_null(m);

	RLC_TRY {
		bn_new(m);

		if (hash) {
			memcpy(h, msg, RLC_MD_LEN);
		} else {
			md_map(h, msg, msg_len);
		}

		bn_read_bin(m, sig, sig_len);
		if (bn_cmp(m, pub->crt->n) == RLC_LT) {
			bn_mxp(m, m, pub->e, pub->crt->n);
			if (bn_bits(m) <= em_bits) {
				bn_write_bin(em, RLC_CEIL(em_bits, 8), m);
				result = pad_ver(em, em_bits, h);
			}
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(m);
		RLC_FREE(em);
	}

	return result;
}
