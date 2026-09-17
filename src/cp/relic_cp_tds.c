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
 * Implementation of the time-deniable signature scheme in groups of unknown
 * order.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Domain separation tag of the hash-to-group function.
 */
#define TDS_DST_GRP		"RELIC-TDS-V01-HASH-TO-GROUP"

/**
 * Domain separation tag of the challenge oracle of the proof of exponentiation.
 */
#define TDS_DST_PRM		"RELIC-TDS-V01-HASH-TO-PRIME"

/**
 * Bit length of a challenge prime, twice the security level.
 */
#define TDS_PRM_BITS	256

/**
 * Upper bound on the number of buckets in the witness assembly.
 */
#define TDS_MAX_BUCKS	1024

/**
 * Largest exponent, in bits, raised to by a binary ladder rather than by the
 * general modular exponentiation.
 */
#define TDS_EXP_SMALL	16

/**
 * Upper bound on the number of powers retained by the witness assembly.
 */
#define TDS_MAX_POWS	4096

/**
 * Upper bound on the number of window digits retained by the witness assembly.
 */
#define TDS_MAX_DIGS	(1 << 24)

/**
 * Writes the public key prefix binding an oracle evaluation to a key.
 *
 * @param[out] bin			- the resulting byte vector.
 * @param[in] key			- the key pair.
 * @return the number of bytes written.
 */
static size_t tds_write_key(uint8_t *bin, const tds_t key) {
	size_t nl = bn_size_bin(key->n);

	bn_write_bin(bin, nl, key->n);
	bn_write_bin(bin + nl, nl, key->e);
	util_write_size(bin + 2 * nl, key->t);
	util_write_size(bin + 2 * nl + 8, key->l);
	return 2 * nl + 16;
}

/**
 * Multiplies two group elements, reducing the product to the canonical
 * representative of its class.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first element.
 * @param[in] b				- the second element.
 * @param[in] n				- the modulus.
 * @param[in] h				- the largest canonical representative.
 * @param[in,out] t			- a temporary value.
 */
static void tds_mul(bn_t c, const bn_t a, const bn_t b, const bn_t n,
		const bn_t h, bn_t t) {
	bn_mul(t, a, b);
	bn_mod_basic(c, t, n);
	if (bn_cmp(c, h) == RLC_GT) {
		bn_sub(c, n, c);
	}
}

/**
 * Squares a group element, reducing the result to the canonical representative
 * of its class.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to square.
 * @param[in] n				- the modulus.
 * @param[in] h				- the largest canonical representative.
 * @param[in,out] t			- a temporary value.
 */
static void tds_sqr(bn_t c, const bn_t a, const bn_t n, const bn_t h, bn_t t) {
	bn_sqr(t, a);
	bn_mod_basic(c, t, n);
	if (bn_cmp(c, h) == RLC_GT) {
		bn_sub(c, n, c);
	}
}

/**
 * Exponentiates a group element by an arbitrary integer. Only the canonical
 * representative is returned, so the folding along the chain below decides a
 * sign that the last one settles again.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to exponentiate.
 * @param[in] b				- the exponent.
 * @param[in] n				- the modulus.
 * @param[in] h				- the largest canonical representative.
 */
static void tds_exp(bn_t c, const bn_t a, const bn_t b, const bn_t n,
		const bn_t h) {
	size_t bits = bn_bits(b);

	/*
	 * The chain advances by raising to the public exponent, which is a very
	 * small number, and a general modular exponentiation spends more on its
	 * own arrangements than on the squaring and multiplication it amounts to.
	 * Here that is not merely waste: the delay is calibrated to the cost of
	 * this step, so an adversary who computes the chain by the ladder below
	 * walks it faster than the reference does, and the delay parameter would
	 * have to absorb the difference. A ladder over the bits of the exponent
	 * closes the gap for the small exponents the chain uses; larger ones keep
	 * the general routine, which wins once the setup is amortised.
	 *
	 * The accumulator is separate from the result so that the usual call,
	 * which passes the same element as input and output, is safe.
	 */
	if (bits > 1 && bits <= TDS_EXP_SMALL) {
		bn_t t, u;

		bn_null(t);
		bn_null(u);

		RLC_TRY {
			bn_new(t);
			bn_new(u);
			bn_copy(u, a);
			for (size_t i = bits - 1; i-- > 0; ) {
				tds_sqr(u, u, n, h, t);
				if (bn_get_bit(b, i)) {
					tds_mul(u, u, a, n, h, t);
				}
			}
			bn_copy(c, u);
		}
		RLC_CATCH_ANY {
			RLC_THROW(ERR_CAUGHT);
		}
		RLC_FINALLY {
			bn_free(t);
			bn_free(u);
		}
		return;
	}

	bn_mxp(c, a, b, n);
	if (bn_cmp(c, h) == RLC_GT) {
		bn_sub(c, n, c);
	}
}

/**
 * Exponentiates a group element with an exponent reduced modulo the group
 * order, using the factorization of the modulus. The signer knows the
 * factorization, so every exponentiation it performs takes this path.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the element to exponentiate.
 * @param[in] b				- the exponent.
 * @param[in] prv			- the private key.
 * @param[in] h				- the largest canonical representative.
 */
static void tds_exp_crt(bn_t c, const bn_t a, const bn_t b, const tds_t prv,
		const bn_t h) {
	bn_t t, u, v;

	bn_null(t);
	bn_null(u);
	bn_null(v);

	RLC_TRY {
		bn_new(t);
		bn_new(u);
		bn_new(v);

		bn_sub_dig(t, prv->crt->p, 1);
		bn_mod_basic(u, b, t);
		bn_sub_dig(t, prv->crt->q, 1);
		bn_mod_basic(v, b, t);
		bn_mxp_crt(c, a, u, v, prv->crt, 0);
		if (bn_cmp(c, h) == RLC_GT) {
			bn_sub(c, prv->n, c);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(u);
		bn_free(v);
	}
}

/**
 * Tests if a value is the canonical representative of a group element.
 *
 * @param[in] a				- the value to test.
 * @param[in] n				- the modulus.
 * @param[in] h				- the largest canonical representative.
 * @return 1 if the value is a group element, 0 otherwise.
 */
static int tds_is_valid(const bn_t a, const bn_t n, const bn_t h) {
	int result = 0;
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);
		if (!bn_is_zero(a) && bn_sign(a) == RLC_POS &&
				bn_cmp(a, h) != RLC_GT) {
			bn_gcd(t, a, n);
			result = (bn_cmp_dig(t, 1) == RLC_EQ);
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(t);
	}

	return result;
}

/**
 * Evaluates the hash-to-group function on a message, a timestamp, a timestamp
 * representative and a salt. The message is compressed first, so that the
 * length of the oracle input is independent of the length of the message.
 *
 * @param[out] c			- the resulting group element.
 * @param[in] msg			- the message.
 * @param[in] len			- the length of the message in bytes.
 * @param[in] stamp			- the timestamp.
 * @param[in] z				- the timestamp representative.
 * @param[in] salt			- the salt.
 * @param[in] key			- the key pair.
 * @param[in] h				- the largest canonical representative.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int tds_map_group(bn_t c, const uint8_t *msg, size_t len, size_t stamp,
		const bn_t z, const uint8_t *salt, const tds_t key, const bn_t h) {
	int result = RLC_ERR;
	size_t pl, nl = bn_size_bin(key->n);
	size_t ol = nl + RLC_MD_LEN;
	size_t il = 2 * nl + 16 + 8 + nl + RLC_TDS_SALT + 8 + RLC_MD_LEN;
	uint8_t *in = RLC_ALLOCA(uint8_t, il), *out = RLC_ALLOCA(uint8_t, ol);
	uint8_t seed[RLC_MD_LEN + 1];
	bn_t t, u;

	if (in == NULL || out == NULL) {
		RLC_FREE(in);
		RLC_FREE(out);
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(t);
		bn_new(u);

		pl = tds_write_key(in, key);
		util_write_size(in + pl, stamp);
		bn_write_bin(in + pl + 8, nl, z);
		memcpy(in + pl + 8 + nl, salt, RLC_TDS_SALT);
		util_write_size(in + pl + 8 + nl + RLC_TDS_SALT, len);
		md_map(in + pl + 16 + nl + RLC_TDS_SALT, msg, len);

		/* Compress the statement once, so that the expansion below runs on a
		 * short input regardless of the size of the modulus. */
		md_map(seed, in, il);

		for (size_t i = 0; i < 256; i++) {
			seed[RLC_MD_LEN] = (uint8_t)i;
			md_xmd(out, ol, seed, RLC_MD_LEN + 1, (const uint8_t *)TDS_DST_GRP,
					strlen(TDS_DST_GRP));
			bn_read_bin(t, out, ol);
			bn_mod_basic(t, t, key->n);
			bn_gcd(u, t, key->n);
			if (bn_cmp_dig(u, 1) == RLC_EQ) {
				/* Square into the subgroup of squares. */
				tds_sqr(c, t, key->n, h, u);
				if (!bn_is_zero(c) && bn_cmp_dig(c, 1) != RLC_EQ) {
					result = RLC_OK;
					break;
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(u);
		RLC_FREE(in);
		RLC_FREE(out);
	}

	return result;
}

/**
 * Evaluates the challenge oracle of the proof of exponentiation, returning a
 * prime of twice the security level in bits.
 *
 * @param[out] l			- the resulting prime.
 * @param[in] g				- the base of the statement.
 * @param[in] y				- the result of the statement.
 * @param[in] k				- the number of exponentiations.
 * @param[in] key			- the key pair.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int tds_map_prime(bn_t l, const bn_t g, const bn_t y, size_t k,
		const tds_t key) {
	int result = RLC_ERR;
	size_t pl, nl = bn_size_bin(key->n);
	size_t il = 2 * nl + 16 + 8 + 2 * nl;
	uint8_t *in = RLC_ALLOCA(uint8_t, il);

	if (in == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	RLC_TRY {
		pl = tds_write_key(in, key);
		util_write_size(in + pl, k);
		bn_write_bin(in + pl + 8, nl, g);
		bn_write_bin(in + pl + 8 + nl, nl, y);

		result = bn_map_prime(l, NULL, in, il, TDS_PRM_BITS, 0,
				(const uint8_t *)TDS_DST_PRM, strlen(TDS_DST_PRM));
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		RLC_FREE(in);
	}

	return result;
}

/**
 * Computes a witness for a proof of exponentiation from the group order.
 *
 * @param[out] pi			- the resulting witness.
 * @param[in] g				- the base of the statement.
 * @param[in] y				- the result of the statement.
 * @param[in] k				- the number of exponentiations.
 * @param[in] prv			- the private key.
 * @param[in] h				- the largest canonical representative.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int tds_poe_prv(bn_t pi, const bn_t g, const bn_t y, size_t k,
		const tds_t prv, const bn_t h) {
	int result = RLC_OK;
	bn_t l, q, r, t;

	bn_null(l);
	bn_null(q);
	bn_null(r);
	bn_null(t);

	RLC_TRY {
		bn_new(l);
		bn_new(q);
		bn_new(r);
		bn_new(t);

		result = tds_map_prime(l, g, y, k, prv);
		if (result == RLC_OK) {
			/* Compute r = e^k mod l and the quotient q = (e^k - r)/l. */
			bn_set_dig(t, (dig_t)k);
			bn_mxp(r, prv->e, t, l);
			bn_mxp_basic(q, prv->e, t, prv->ord);
			bn_sub(q, q, r);
			bn_mod_basic(q, q, prv->ord);
			bn_gcd(t, l, prv->ord);
			if (bn_cmp_dig(t, 1) != RLC_EQ) {
				result = RLC_ERR;
			} else {
				bn_mod_inv(t, l, prv->ord);
				bn_mul(r, q, t);
				bn_mod_basic(q, r, prv->ord);
				tds_exp_crt(pi, g, q, prv, h);
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(l);
		bn_free(q);
		bn_free(r);
		bn_free(t);
	}

	return result;
}

/**
 * Computes a witness for a proof of exponentiation by public sequential
 * evaluation, in constant memory.
 *
 * @param[out] pi			- the resulting witness.
 * @param[in] g				- the base of the statement.
 * @param[in] y				- the result of the statement.
 * @param[in] k				- the number of exponentiations.
 * @param[in] pub			- the public key.
 * @param[in] h				- the largest canonical representative.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int tds_poe_pub(bn_t pi, const bn_t g, const bn_t y, size_t k,
		const tds_t pub, const bn_t h) {
	int result = RLC_OK;
	size_t i;
	bn_t l, x, r, b, t, u;

	bn_null(l);
	bn_null(x);
	bn_null(r);
	bn_null(b);
	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(l);
		bn_new(x);
		bn_new(r);
		bn_new(b);
		bn_new(t);
		bn_new(u);

		result = tds_map_prime(l, g, y, k, pub);
		if (result == RLC_OK) {
			/* Maintain x = g^floor(e^i/l) and r = e^i mod l. */
			bn_set_dig(x, 1);
			bn_set_dig(r, 1);
			for (i = 0; i < k; i++) {
				bn_mul(t, r, pub->e);
				bn_div_rem(b, r, t, l);
				tds_exp(x, x, pub->e, pub->n, h);
				if (!bn_is_zero(b)) {
					tds_exp(t, g, b, pub->n, h);
					tds_mul(x, x, t, pub->n, h, u);
				}
			}
			bn_copy(pi, x);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(l);
		bn_free(x);
		bn_free(r);
		bn_free(b);
		bn_free(t);
		bn_free(u);
	}

	return result;
}

/**
 * Evaluates the delayed output by sequential exponentiation, in constant
 * memory, and computes the corresponding witness in a second pass.
 *
 * @param[out] y			- the resulting delayed output.
 * @param[out] pi			- the resulting witness.
 * @param[in] g				- the base.
 * @param[in] k				- the number of exponentiations.
 * @param[in] pub			- the public key.
 * @param[in] h				- the largest canonical representative.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int tds_eval_basic(bn_t y, bn_t pi, const bn_t g, size_t k,
		const tds_t pub, const bn_t h) {
	int result = RLC_OK;
	size_t i;
	bn_t t, u;

	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(t);
		bn_new(u);

		bn_copy(y, g);
		for (i = 0; i < k; i++) {
			tds_exp(y, y, pub->e, pub->n, h);
		}
		result = tds_poe_pub(pi, g, y, k, pub, h);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(u);
	}

	return result;
}

/**
 * Evaluates the delayed output by sequential exponentiation, retaining powers
 * of the base as the exponentiation chain advances, and assembles the witness
 * from them once the challenge is known.
 *
 * Writing the quotient in base e, the witness is the product of the retained
 * powers raised to the corresponding window digits. The digits are collected
 * into buckets, which are then combined by a descent, so that the assembly
 * costs about k/w multiplications for a window of w digits instead of the k
 * exponentiations of the second pass of tds_eval_basic().
 *
 * @param[out] y			- the resulting delayed output.
 * @param[out] pi			- the resulting witness.
 * @param[in] g				- the base.
 * @param[in] k				- the number of exponentiations.
 * @param[in] pub			- the public key.
 * @param[in] h				- the largest canonical representative.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int tds_eval_quick(bn_t y, bn_t pi, const bn_t g, size_t k,
		const tds_t pub, const bn_t h) {
	int result = RLC_OK;
	size_t i, m, v, w, nb, np, nd, base, bucks, gamma, kappa;
	bn_t *pows = NULL, *buck = NULL;
	dig_t *digs = NULL, d, e, pe[64];
	bn_t l, x, r, b, t, u, a, s;

	e = (bn_bits(pub->e) <= RLC_DIG - 1 ? pub->e->dp[0] : 0);
	if (e < 2 || k < 64) {
		return tds_eval_basic(y, pi, g, k, pub, h);
	}

	/* Select the window such that the number of buckets is bounded, and the
	 * stride such that the number of retained powers is bounded. */
	w = 1;
	bucks = e;
	pe[0] = 1;
	while (bucks <= TDS_MAX_BUCKS / e) {
		pe[w] = bucks;
		bucks *= e;
		w++;
	}
	nb = (k + w - 1) / w;
	gamma = (nb + TDS_MAX_POWS - 1) / TDS_MAX_POWS;
	gamma = (gamma == 0 ? 1 : gamma);
	kappa = w * gamma;
	np = (k + kappa - 1) / kappa;
	nd = np * gamma;

	if (nd > TDS_MAX_DIGS) {
		return tds_eval_basic(y, pi, g, k, pub, h);
	}

	bn_null(l);
	bn_null(x);
	bn_null(r);
	bn_null(b);
	bn_null(t);
	bn_null(u);
	bn_null(a);
	bn_null(s);

	RLC_TRY {
		bn_new(l);
		bn_new(x);
		bn_new(r);
		bn_new(b);
		bn_new(t);
		bn_new(u);
		bn_new(a);
		bn_new(s);

		pows = (bn_t *)calloc(np, sizeof(bn_t));
		buck = (bn_t *)calloc(bucks, sizeof(bn_t));
		digs = (dig_t *)calloc(nd, sizeof(dig_t));
		if (pows == NULL || buck == NULL || digs == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
			result = RLC_ERR;
		} else {
			for (i = 0; i < np; i++) {
				bn_null(pows[i]);
				bn_new(pows[i]);
			}
			for (i = 0; i < bucks; i++) {
				bn_null(buck[i]);
				bn_new(buck[i]);
			}

			/* Sequential phase, retaining one power every kappa steps. */
			bn_copy(x, g);
			for (i = 0; i < k; i++) {
				if (i % kappa == 0) {
					bn_copy(pows[i / kappa], x);
				}
				tds_exp(x, x, pub->e, pub->n, h);
			}
			bn_copy(y, x);

			result = tds_map_prime(l, g, y, k, pub);
			if (result == RLC_OK) {
				/* Collect the window digits of the quotient. The digit of place
				 * p = k - i is the i-th quotient of the long division. */
				bn_set_dig(r, 1);
				for (i = 1; i <= k; i++) {
					bn_mul(t, r, pub->e);
					bn_div_rem(b, r, t, l);
					if (!bn_is_zero(b)) {
						d = b->dp[0];
						m = k - i;
						digs[(m / kappa) * gamma + (m % kappa) / w] +=
								d * pe[(m % kappa) % w];
					}
				}

				/* Assemble the witness, folding the strides by Horner's rule. */
				for (v = gamma; v-- > 0; ) {
					for (base = 1; base < bucks; base++) {
						bn_set_dig(buck[base], 1);
					}
					for (m = 0; m < np; m++) {
						d = digs[m * gamma + v];
						if (d != 0) {
							tds_mul(buck[d], buck[d], pows[m], pub->n, h, t);
						}
					}
					bn_set_dig(a, 1);
					bn_set_dig(s, 1);
					for (base = bucks; base-- > 1; ) {
						tds_mul(a, a, buck[base], pub->n, h, t);
						tds_mul(s, s, a, pub->n, h, t);
					}
					if (v == gamma - 1) {
						bn_copy(pi, s);
					} else {
						bn_set_dig(t, (dig_t)bucks);
						tds_exp(pi, pi, t, pub->n, h);
						tds_mul(pi, pi, s, pub->n, h, t);
					}
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		if (pows != NULL) {
			for (i = 0; i < np; i++) {
				bn_free(pows[i]);
			}
			free(pows);
		}
		if (buck != NULL) {
			for (i = 0; i < bucks; i++) {
				bn_free(buck[i]);
			}
			free(buck);
		}
		if (digs != NULL) {
			free(digs);
		}
		bn_free(l);
		bn_free(x);
		bn_free(r);
		bn_free(b);
		bn_free(t);
		bn_free(u);
		bn_free(a);
		bn_free(s);
	}

	return result;
}

/**
 * Verifies a proof of exponentiation.
 *
 * @param[in] pi			- the witness.
 * @param[in] g				- the base of the statement.
 * @param[in] y				- the result of the statement.
 * @param[in] k				- the number of exponentiations.
 * @param[in] pub			- the public key.
 * @param[in] h				- the largest canonical representative.
 * @return 1 if the proof is valid, 0 otherwise.
 */
static int tds_poe_ver(const bn_t pi, const bn_t g, const bn_t y, size_t k,
		const tds_t pub, const bn_t h) {
	int result = 0;
	bn_t l, r, t, u;

	bn_null(l);
	bn_null(r);
	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(l);
		bn_new(r);
		bn_new(t);
		bn_new(u);

		/* The base and the result are either public parameters or already
		 * validated by the caller, so only the witness is tested here. */
		if (tds_is_valid(pi, pub->n, h)) {
			if (tds_map_prime(l, g, y, k, pub) == RLC_OK) {
				bn_set_dig(t, (dig_t)k);
				bn_mxp(r, pub->e, t, l);
				bn_mxp_sim(u, pi, l, g, r, pub->n);
				if (bn_cmp(u, h) == RLC_GT) {
					bn_sub(u, pub->n, u);
				}
				result = (bn_cmp(u, y) == RLC_EQ);
			}
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(l);
		bn_free(r);
		bn_free(t);
		bn_free(u);
	}

	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_tds_gen(tds_t pub, tds_t prv, size_t bits, size_t delay, size_t bound) {
	int result = RLC_OK;
	bn_t p, q, t, u, h;

	if (bits < 128 || delay < 1 || bound < 1) {
		return RLC_ERR;
	}

	bn_null(p);
	bn_null(q);
	bn_null(t);
	bn_null(u);
	bn_null(h);

	RLC_TRY {
		bn_new(p);
		bn_new(q);
		bn_new(t);
		bn_new(u);
		bn_new(h);

		bn_set_dig(prv->e, RLC_TDS_EXPO);

		do {
			/* Sample p = q = 3 mod 4, so that -1 is not a square. */
			do {
				bn_gen_prime(p, bits / 2);
			} while (bn_get_bit(p, 1) == 0);
			do {
				bn_gen_prime(q, bits / 2);
			} while (bn_get_bit(q, 1) == 0 || bn_cmp(p, q) == RLC_EQ);

			/* Compute the order of the quotient group, phi(n) / 2. */
			bn_sub_dig(t, p, 1);
			bn_sub_dig(u, q, 1);
			bn_mul(prv->ord, t, u);
			bn_hlv(prv->ord, prv->ord);
			bn_gcd(t, prv->e, prv->ord);
		} while (bn_cmp_dig(t, 1) != RLC_EQ);

		bn_mul(prv->n, p, q);
		bn_mod_inv(prv->d, prv->e, prv->ord);
		bn_hlv(h, prv->n);

		/* Retain the factorization for exponentiation by the CRT. */
		bn_copy(prv->crt->p, p);
		bn_copy(prv->crt->q, q);
		bn_copy(prv->crt->n, prv->n);
		bn_mod_inv(prv->crt->qi, q, p);
		bn_zero(prv->crt->dp);
		bn_zero(prv->crt->dq);

		/* Sample the onset value in the subgroup of squares. */
		do {
			bn_rand_mod(t, prv->n);
			bn_gcd(u, t, prv->n);
			if (bn_cmp_dig(u, 1) != RLC_EQ) {
				continue;
			}
			tds_sqr(prv->z, t, prv->n, h, u);
		} while (bn_is_zero(prv->z) || bn_cmp_dig(prv->z, 1) == RLC_EQ);

		prv->t = delay;
		prv->l = bound;

		bn_copy(pub->n, prv->n);
		bn_copy(pub->e, prv->e);
		bn_copy(pub->z, prv->z);
		bn_zero(pub->ord);
		bn_zero(pub->d);
		bn_zero(pub->crt->p);
		bn_zero(pub->crt->q);
		bn_zero(pub->crt->n);
		bn_zero(pub->crt->qi);
		bn_zero(pub->crt->dp);
		bn_zero(pub->crt->dq);
		pub->t = delay;
		pub->l = bound;
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(p);
		bn_free(q);
		bn_free(t);
		bn_free(u);
		bn_free(h);
	}

	return result;
}

int cp_tds_sign(tds_sig_t sig, const uint8_t *salt, const uint8_t *msg,
		size_t len, size_t stamp, const tds_t prv) {
	int result = RLC_OK;
	bn_t a, b, x, h;

	if (stamp < 1 || stamp > prv->l) {
		return RLC_ERR;
	}

	bn_null(a);
	bn_null(b);
	bn_null(x);
	bn_null(h);

	RLC_TRY {
		bn_new(a);
		bn_new(b);
		bn_new(x);
		bn_new(h);

		bn_hlv(h, prv->n);

		if (salt == NULL) {
			rand_bytes(sig->s, RLC_TDS_SALT);
		} else {
			memcpy(sig->s, salt, RLC_TDS_SALT);
		}

		/* Derive the timestamp representative z_t = z_0^(e^-t). */
		bn_set_dig(a, (dig_t)stamp);
		bn_mxp_basic(b, prv->d, a, prv->ord);
		tds_exp_crt(sig->z, prv->z, b, prv, h);

		/* Evaluate the delayed output y = H_G(m, t, z_t, s)^(e^T). */
		result = tds_map_group(x, msg, len, stamp, sig->z, sig->s, prv, h);
		if (result == RLC_OK) {
			bn_set_dig(a, (dig_t)prv->t);
			bn_mxp_basic(b, prv->e, a, prv->ord);
			tds_exp_crt(sig->y, x, b, prv, h);
			result = tds_poe_prv(sig->ts, sig->z, prv->z, stamp, prv, h);
		}
		if (result == RLC_OK) {
			result = tds_poe_prv(sig->del, x, sig->y, prv->t, prv, h);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(a);
		bn_free(b);
		bn_free(x);
		bn_free(h);
	}

	return result;
}

int cp_tds_ver(const tds_sig_t sig, const uint8_t *msg, size_t len,
		size_t stamp, const tds_t pub) {
	int result = 0;
	bn_t x, h;

	if (stamp < 1 || stamp > pub->l) {
		return 0;
	}

	bn_null(x);
	bn_null(h);

	RLC_TRY {
		bn_new(x);
		bn_new(h);

		bn_hlv(h, pub->n);

		if (tds_is_valid(sig->z, pub->n, h) && tds_is_valid(sig->y, pub->n, h)) {
			if (tds_map_group(x, msg, len, stamp, sig->z, sig->s, pub,
					h) == RLC_OK) {
				result = tds_poe_ver(sig->ts, sig->z, pub->z, stamp, pub, h) &&
						tds_poe_ver(sig->del, x, sig->y, pub->t, pub, h);
			}
		}
	}
	RLC_CATCH_ANY {
		result = 0;
	}
	RLC_FINALLY {
		bn_free(x);
		bn_free(h);
	}

	return result;
}

int cp_tds_alt(tds_sig_t alt, const uint8_t *salt, const uint8_t *msg,
		size_t len, size_t stamp, const tds_sig_t sig, const uint8_t *src,
		size_t src_len, size_t src_stamp, const tds_t pub) {
	int result = RLC_OK;
	size_t i;
	bn_t x, t, u, h;

	if (stamp < 1 || stamp > pub->l || src_stamp < 1 || src_stamp > pub->l ||
			stamp > src_stamp) {
		return RLC_ERR;
	}
	if (cp_tds_ver(sig, src, src_len, src_stamp, pub) != 1) {
		return RLC_ERR;
	}

	bn_null(x);
	bn_null(t);
	bn_null(u);
	bn_null(h);

	RLC_TRY {
		bn_new(x);
		bn_new(t);
		bn_new(u);
		bn_new(h);

		bn_hlv(h, pub->n);

		if (salt == NULL) {
			rand_bytes(alt->s, RLC_TDS_SALT);
		} else {
			memcpy(alt->s, salt, RLC_TDS_SALT);
		}

		/* Walk the timestamp chain back to the target timestamp. */
		bn_copy(alt->z, sig->z);
		for (i = 0; i < src_stamp - stamp; i++) {
			tds_exp(alt->z, alt->z, pub->e, pub->n, h);
		}

		result = tds_map_group(x, msg, len, stamp, alt->z, alt->s, pub, h);

		/* Carry out the prescribed sequential work. */
		if (result == RLC_OK) {
			/* The assembly from retained powers falls back on its own when
			 * the delay is too short, or too long, to be worth the memory. */
			result = tds_eval_quick(alt->y, alt->del, x, pub->t, pub, h);
		}
		if (result == RLC_OK) {
			result = tds_poe_pub(alt->ts, alt->z, pub->z, stamp, pub, h);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(x);
		bn_free(t);
		bn_free(u);
		bn_free(h);
	}

	return result;
}

int cp_tds_write_sig(uint8_t *bin, size_t *len, const tds_sig_t sig,
		const tds_t pub) {
	int result = RLC_OK;
	size_t nl = bn_size_bin(pub->n);

	if (*len < 4 * nl + RLC_TDS_SALT) {
		*len = 4 * nl + RLC_TDS_SALT;
		return RLC_ERR;
	}

	RLC_TRY {
		bn_write_bin(bin, nl, sig->z);
		bn_write_bin(bin + nl, nl, sig->y);
		bn_write_bin(bin + 2 * nl, nl, sig->ts);
		bn_write_bin(bin + 3 * nl, nl, sig->del);
		memcpy(bin + 4 * nl, sig->s, RLC_TDS_SALT);
		*len = 4 * nl + RLC_TDS_SALT;
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}

	return result;
}

int cp_tds_read_sig(tds_sig_t sig, const uint8_t *bin, size_t len,
		const tds_t pub) {
	int result = RLC_OK;
	size_t nl = bn_size_bin(pub->n);

	if (len != 4 * nl + RLC_TDS_SALT) {
		return RLC_ERR;
	}

	RLC_TRY {
		bn_read_bin(sig->z, bin, nl);
		bn_read_bin(sig->y, bin + nl, nl);
		bn_read_bin(sig->ts, bin + 2 * nl, nl);
		bn_read_bin(sig->del, bin + 3 * nl, nl);
		memcpy(sig->s, bin + 4 * nl, RLC_TDS_SALT);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}

	return result;
}
