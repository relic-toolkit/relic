/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2018 RELIC Authors
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
 * Implementation of the vBNN-IBS idenenty-based signature algorithm.
 *
 * Paper: "IMBAS: id-based multi-user broadcast authentication in wireless sensor networks"
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_vbnn_gen(bn_t msk, ec_t mpk) {
	int result = RLC_OK;

	/* order of the ECC group */
	bn_t n;

	/* zero variables */
	bn_null(n);

	RLC_TRY {
		/* initialize variables */
		bn_new(n);

		/* get order of ECC group */
		ec_curve_get_ord(n);

		/* calculate master secret key */
		bn_rand_mod(msk, n);

		/* calculate master public key */
		ec_mul_gen(mpk, msk);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		/* free variables */
		bn_free(n);
	}
	return result;
}

int cp_vbnn_gen_prv(bn_t sk, ec_t pk, const bn_t msk, const uint8_t *id,
		size_t id_len) {
	/* Room for the point in compressed form, whatever it is. */
	uint8_t hash[RLC_MD_LEN], buf[1 + RLC_FC_BYTES];
	const uint8_t *in[2] = { id, buf };
	size_t lens[2] = { id_len, 0 };
	bn_t n, r;
	int result = RLC_OK;

	/* zero variables */
	bn_null(n);
	bn_null(r);

	RLC_TRY {
		/* initialize variables */
		bn_new(n);
		bn_new(r);

		/* get order of ECC group */
		ec_curve_get_ord(n);

		/* extract user key from id */
		bn_rand_mod(r, n);

		/* calculate R part of the user key */
		ec_mul_gen(pk, r);

		/* calculate s part of the user key */
		lens[1] = ec_size_bin(pk, 1);
		ec_write_bin(buf, lens[1], pk, 1);
		md_map_lot(hash, in, lens, 2);
		bn_read_bin(sk, hash, RLC_MD_LEN);
		bn_mod(sk, sk, n);
		bn_mul(sk, sk, msk);
		bn_add(sk, sk, r);
		bn_mod(sk, sk, n);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		/* free variables */
		bn_free(n);
		bn_free(r);
	}
	return result;
}

int cp_vbnn_sig(ec_t r, bn_t z, bn_t h, const uint8_t *id, size_t id_len,
		const uint8_t *msg, int msg_len, const bn_t sk, const ec_t pk) {
	/* Room for both points in compressed form, whatever they are. */
	uint8_t hash[RLC_MD_LEN], buf[2 * (1 + RLC_FC_BYTES)];
	const uint8_t *in[3] = { id, msg, buf };
	size_t lens[3] = { id_len, (size_t)msg_len, 0 };
	bn_t n, y;
	ec_t t;
	int result = RLC_OK;

	if (msg_len < 0) {
		return RLC_ERR;
	}

	/* zero variables */
	bn_null(n);
	bn_null(y);
	ec_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(y);
		ec_new(t);

		/* get order of ECC group */
		ec_curve_get_ord(n);

		bn_rand_mod(y, n);
		ec_mul_gen(t, y);

		/* calculate h part of the signature */
		ec_write_bin(buf, ec_size_bin(pk, 1), pk, 1);
		lens[2] = ec_size_bin(pk, 1);
		ec_write_bin(buf + lens[2], ec_size_bin(t, 1), t, 1);
		lens[2] += ec_size_bin(t, 1);
		md_map_lot(hash, in, lens, 3);
		bn_read_bin(h, hash, RLC_MD_LEN);
		bn_mod(h, h, n);

		/* calculate z part of the signature */
		bn_mul(z, h, sk);
		bn_add(z, z, y);
		bn_mod(z, z, n);

		/* calculate R part of the signature */
		ec_copy(r, pk);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		/* free variables */
		bn_free(n);
		bn_free(y);
		ec_free(t);
	}
	return result;
}

int cp_vbnn_ver(const ec_t r, const bn_t z, const bn_t h, const uint8_t *id,
		size_t id_len, const uint8_t *msg, int msg_len, const ec_t mpk) {
	/* Room for both points r and Z in compressed form, whatever they are. */
	uint8_t hash[RLC_MD_LEN], buf[2 * (1 + RLC_FC_BYTES)];
	const uint8_t *in[3] = { id, msg, buf };
	size_t lens[3] = { id_len, (size_t)msg_len, 0 };
	bn_t n, c, _h;
	ec_t Z, t;
	int result = 0;

	/* The point r comes from the signature, so it must be in the group of
	 * prime order. */
	if (msg_len < 0 || !ec_is_valid(r)) {
		return 0;
	}

	/* zero variables */
	bn_null(n);
	bn_null(c);
	bn_null(_h);
	ec_null(Z);
	ec_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(c);
		bn_new(_h);
		ec_new(Z);
		ec_new(t);

		/* get order of ECC group */
		ec_curve_get_ord(n);

		/* Compute c = H(id || r), leaving out the message for now. */
		lens[1] = 0;
		lens[2] = ec_size_bin(r, 1);
		ec_write_bin(buf, lens[2], r, 1);
		md_map_lot(hash, in, lens, 3);
		bn_read_bin(c, hash, RLC_MD_LEN);
		bn_mod(c, c, n);

		/* calculate Z */
		ec_mul_gen(Z, z);
		/* [h]([c]mpk + R) = [hc]mpk + [h]R, in one simultaneous product. */
		bn_mul(c, c, h);
		bn_mod(c, c, n);
		ec_mul_sim(t, mpk, c, r, h);
		ec_sub(Z, Z, t);
		ec_norm(Z, Z);

		/* calculate h_verify */
		lens[1] = (size_t)msg_len;
		ec_write_bin(buf + lens[2], ec_size_bin(Z, 1), Z, 1);
		lens[2] += ec_size_bin(Z, 1);
		md_map_lot(hash, in, lens, 3);
		bn_read_bin(_h, hash, RLC_MD_LEN);
		bn_mod(_h, _h, n);

		/* A response z outside [0, n) would give another valid signature. */
		result = (bn_cmp(h, _h) == RLC_EQ && bn_sign(z) == RLC_POS &&
				bn_cmp(z, n) == RLC_LT);
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		/* free variables */
		bn_free(n);
		bn_free(c);
		bn_free(_h);
		ec_free(Z);
		ec_free(t);
	}
	return result;
}
