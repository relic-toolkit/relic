/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developsmlers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the vsmlersion 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or vsmlersion 2.0 of the Apache
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
 * Implementation of same-message linkable extendable ring signatures, from
 * "Count Me In! Extendability for Threshold Ring Signatures" by Aranha,
 * Hall-Andersen, Nitulescu, Pagnin and Yakoubov (PKC 2022):
 * https://eprint.iacr.org/2021/1240.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_smlers_sig(bn_t td, smlers_t p, const uint8_t *msg, size_t len,
		const bn_t sk, const ec_t pk, const ec_t pp) {
	bn_t n;
	ec_t g[2], y[2];
	uint8_t *buf = RLC_ALLOCA(uint8_t, RLC_MD_LEN + len);
	int result = RLC_OK;

	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(n);
	ec_null(g[0]);
	ec_null(g[1]);
	ec_null(y[0]);
	ec_null(y[1]);

	RLC_TRY {
		bn_new(n);
		ec_new(g[0]);
		ec_new(g[1]);
		ec_new(y[0]);
		ec_new(y[1]);

		/* Compute h = pp - [td]G, so that the signer does not know log(h). */
		ec_curve_get_ord(n);
		bn_rand_mod(td, n);
		ec_mul_gen(p->h, td);
		ec_sub(p->h, pp, p->h);
		ec_norm(p->h, p->h);
		ec_copy(p->pk, pk);

		/* Compute the linkability tag tau = [sk]H(m). */
		ec_curve_get_gen(g[0]);
		ec_map(g[1], msg, len);
		ec_mul(p->tau, g[1], sk);

		/* Prove the relation h = [x]G or (pk = [x]G and tau = [x]H(m)),
		 * signing the message with a fresh nonce shared by the signature. */
		rand_bytes(p->nonce, RLC_MD_LEN);
		memcpy(buf, p->nonce, RLC_MD_LEN);
		memcpy(buf + RLC_MD_LEN, msg, len);
		ec_copy(y[0], p->pk);
		ec_copy(y[1], p->tau);
		if (cp_sokeqor_sig(p->c, p->r, buf, RLC_MD_LEN + len, p->h, y, g, sk,
				0) != RLC_OK) {
			RLC_THROW(ERR_CAUGHT);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		ec_free(g[0]);
		ec_free(g[1]);
		ec_free(y[0]);
		ec_free(y[1]);
		RLC_FREE(buf);
	}
	return result;
}

int cp_smlers_ver(bn_t td, smlers_t *s, size_t size, const uint8_t *msg,
		size_t len, const ec_t pp) {
	ec_t t, g[2], y[2];
	uint8_t *buf;
	int flag = 0, result = 0;

	if (size == 0) {
		return 0;
	}

	buf = RLC_ALLOCA(uint8_t, RLC_MD_LEN + len);
	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}

	ec_null(t);
	ec_null(g[0]);
	ec_null(g[1]);
	ec_null(y[0]);
	ec_null(y[1]);

	RLC_TRY {
		ec_new(t);
		ec_new(g[0]);
		ec_new(g[1]);
		ec_new(y[0]);
		ec_new(y[1]);

		ec_mul_gen(t, td);
		ec_curve_get_gen(g[0]);
		ec_map(g[1], msg, len);

		for (size_t i = 0; i < size; i++) {
			ec_add(t, t, s[i]->h);
		}
		if (ec_cmp(pp, t) == RLC_EQ) {
			flag = 1;
			memcpy(buf, s[0]->nonce, RLC_MD_LEN);
			memcpy(buf + RLC_MD_LEN, msg, len);
			for (size_t i = 0; i < size; i++) {
				/* All members carry the nonce and tag of the same signer. */
				flag &= (memcmp(s[i]->nonce, s[0]->nonce, RLC_MD_LEN) == 0);
				flag &= (ec_cmp(s[i]->tau, s[0]->tau) == RLC_EQ);
				ec_copy(y[0], s[i]->pk);
				ec_copy(y[1], s[i]->tau);
				flag &= cp_sokeqor_ver(s[i]->c, s[i]->r, buf, RLC_MD_LEN + len,
						s[i]->h, y, g);
			}
			result = flag;
		}
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ec_free(t);
		ec_free(g[0]);
		ec_free(g[1]);
		ec_free(y[0]);
		ec_free(y[1]);
		RLC_FREE(buf);
	}
	return result;
}

int cp_smlers_ext(bn_t td, smlers_t *p, size_t *size, const uint8_t *msg,
		size_t len, const ec_t pk) {
	bn_t n, r;
	ec_t g[2], y[2];
	uint8_t *buf;
	int result = RLC_OK;

	/* The new member takes its nonce and tag from the last one in the ring. */
	if (*size == 0) {
		return RLC_ERR;
	}

	for (size_t i = 0; i < *size; i++) {
		if (ec_cmp(pk, p[i]->pk) == RLC_EQ) {
			return RLC_ERR;
		}
	}

	buf = RLC_ALLOCA(uint8_t, RLC_MD_LEN + len);
	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(n);
	bn_null(r);
	ec_null(g[0]);
	ec_null(g[1]);
	ec_null(y[0]);
	ec_null(y[1]);

	RLC_TRY {
		bn_new(n);
		bn_new(r);
		ec_new(g[0]);
		ec_new(g[1]);
		ec_new(y[0]);
		ec_new(y[1]);

		/* Compute h = [r]G for a fresh trapdoor r. */
		ec_curve_get_ord(n);
		bn_rand_mod(r, n);
		ec_mul_gen(p[*size]->h, r);
		ec_copy(p[*size]->pk, pk);
		ec_copy(p[*size]->tau, p[*size - 1]->tau);
		memcpy(p[*size]->nonce, p[*size - 1]->nonce, RLC_MD_LEN);

		/* Prove the same relation, using the trapdoor r as the witness. */
		ec_curve_get_gen(g[0]);
		ec_map(g[1], msg, len);
		memcpy(buf, p[*size]->nonce, RLC_MD_LEN);
		memcpy(buf + RLC_MD_LEN, msg, len);
		ec_copy(y[0], p[*size]->pk);
		ec_copy(y[1], p[*size]->tau);
		if (cp_sokeqor_sig(p[*size]->c, p[*size]->r, buf, RLC_MD_LEN + len,
				p[*size]->h, y, g, r, 1) != RLC_OK) {
			RLC_THROW(ERR_CAUGHT);
		} else {
			/* Update the trapdoor only once the member was added. */
			bn_sub(td, td, r);
			bn_mod(td, td, n);
			(*size)++;
			result = RLC_OK;
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		bn_free(r);
		ec_free(g[0]);
		ec_free(g[1]);
		ec_free(y[0]);
		ec_free(y[1]);
		RLC_FREE(buf);
	}
	return result;
}
