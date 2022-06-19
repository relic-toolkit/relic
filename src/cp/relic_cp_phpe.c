/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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
 * Implementation of Paillier's Homomorphic Probabilistic Encryption.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_phpe_gen(bn_t pub, phpe_t prv, size_t bits) {
	int result = RLC_OK;

	/* Generate primes p and q of equivalent length. */
	do {
		bn_gen_prime(prv->p, bits / 2);
		bn_gen_prime(prv->q, bits / 2);
	} while (bn_cmp(prv->p, prv->q) == RLC_EQ);

	/* Compute n = pq. */
	bn_mul(prv->n, prv->p, prv->q);

#ifdef CP_CRT
	/* Fix g = n + 1. */

	/* Precompute dp = 1/(pow(g, p-1, p^2)//p mod p.
       with g=1+n, this is also 1/((p-1)q) mod p.
     */
 	bn_sub_dig(prv->dp, prv->p, 1);			//p-1
 	bn_mul(prv->dp, prv->dp, prv->q);		//(p-1)q
	bn_mod(prv->dp, prv->dp, prv->p);		//(p-1)q mod p
	bn_mod_inv(prv->dp, prv->dp, prv->p);	//((p-1)q)^{-1} mod p

    /* Precompute dq = 1/(pow(g, q-1, q^2)//q mod q.
       with g=1+n, this is also 1/((q-1)p) mod q.
     */
 	bn_sub_dig(prv->dq, prv->q, 1);			//q-1
 	bn_mul(prv->dq, prv->dq, prv->p);		//(q-1)p
	bn_mod(prv->dq, prv->dq, prv->q);		//(q-1)p mod q
	bn_mod_inv(prv->dq, prv->dq, prv->q);	//((q-1)p)^{-1} mod q

	/* qInv = q^(-1) mod p. */
	bn_mod_inv(prv->qi, prv->q, prv->p);
#endif

	bn_copy(pub, prv->n);
	return result;
}

int cp_phpe_add(bn_t r, const bn_t c, const bn_t d, const bn_t pub) {
	int result = RLC_OK;
	bn_t s;

	bn_null(s);

	RLC_TRY {
		bn_new(s);

		bn_sqr(s, pub);
		bn_mul(r, c, d);
		bn_mod(r, r, s);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(s);
	}

	return result;
}

int cp_phpe_enc(bn_t c, const bn_t m, const bn_t pub) {
	bn_t g, r, s;
	int result = RLC_OK;

	bn_null(g);
	bn_null(r);
	bn_null(s);

	if (pub == NULL || bn_bits(m) > bn_bits(pub)) {
		return RLC_ERR;
	}

	RLC_TRY {
		bn_new(g);
		bn_new(r);
		bn_new(s);

		/* Generate r in Z_n^*. */
		bn_rand_mod(r, pub);
		/* Compute c = (g^m)(r^n) mod n^2.
			with g=1+n, this is also (1+nm)r^n mod n^2.
		*/
		bn_add_dig(g, pub, 1);
		bn_sqr(s, pub);
		bn_mul(c, pub, m);
        bn_add_dig(c, c, 1);
		bn_mod(c, c, s);
		bn_mxp(r, r, pub, s);
		bn_mul(c, c, r);
		bn_mod(c, c, s);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(g);
		bn_free(r);
		bn_free(s);
	}

	return result;
}

int cp_phpe_dec(bn_t m, const bn_t c, const phpe_t prv) {
	bn_t t, u;
	int result = RLC_OK;

	if (prv == NULL || bn_bits(c) > 2 * bn_bits(prv->n)) {
		return RLC_ERR;
	}

	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(t);
		bn_new(u);

		bn_sub_dig(t, prv->p, 1);
		bn_sub_dig(u, prv->q, 1);

#if !defined(CP_CRT)
		bn_mul(t, t, u);
		/* Compute (c^l mod n^2) * u mod n. */
		bn_sqr(u, prv->n);
		bn_mxp(m, c, t, u);

		bn_sub_dig(m, m, 1);
		bn_div(m, m, prv->n);
		bn_mod_inv(u, t, prv->n);
		bn_mul(m, m, u);
		bn_mod(m, m, prv->n);
#else
		bn_mxp_crt(m, c, t, u, prv, 1);
#endif /* CP_CRT */
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(t);
		bn_free(u);
	}

	return result;
}
