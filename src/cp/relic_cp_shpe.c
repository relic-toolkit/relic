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
 * Implementation of Paillier's Subgroup-variant
 *                   Homomorphic Probabilistic Encryption.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_shpe_gen(shpe_t pub, shpe_t prv, int sbits, int nbits) {
	int result = RLC_OK;

    if (sbits > (nbits/2)) {
        return RLC_ERR;
    }

	/* Generate primes p and q of equivalent length
       and (p-1) has a prime factor (the subgroup order) of length sbits
     */
	do {
		bn_gen_factor_prime(prv->a, prv->crt->p, sbits, nbits / 2);
		bn_gen_prime(prv->crt->q, nbits / 2);
	} while (bn_cmp(prv->crt->p, prv->crt->q) == RLC_EQ);

	/* Compute n = pq. */
	bn_mul(prv->crt->n, prv->crt->p, prv->crt->q);

    /* compute the subgroup size */
	bn_sub_dig(prv->crt->p, prv->crt->p, 1);
	bn_sub_dig(prv->crt->q, prv->crt->q, 1);
    bn_mul(pub->g, prv->crt->p, prv->crt->q);	// lambda = (p-1)(q-1)
    bn_div(prv->b, pub->g, prv->a);	// lambda = a*b

	/* Restore p and q. */
	bn_add_dig(prv->crt->p, prv->crt->p, 1);
	bn_add_dig(prv->crt->q, prv->crt->q, 1);

    /* Fix the generator to be g=(1+n)^b */

	/* Compute dp and dq. */
    /* dp is 1/((q-1)*lambda) mod p */
    bn_mod(prv->crt->dp, pub->g, prv->crt->p);
    bn_mul(prv->crt->dp, prv->crt->dp, prv->crt->q);
    bn_mod(prv->crt->dp, prv->crt->dp, prv->crt->p);

    /* dq is 1/((p-1)*lambda) mod q */
    bn_mod(prv->crt->dq, pub->g, prv->crt->q);
    bn_mul(prv->crt->dq, prv->crt->dq, prv->crt->p);
    bn_mod(prv->crt->dq, prv->crt->dq, prv->crt->q);

    /* invertions */
	bn_mod_inv(prv->crt->dp, prv->crt->dp, prv->crt->p);
	bn_mod_inv(prv->crt->dq, prv->crt->dq, prv->crt->q);

    /* Precompute (1+n)^b)^n mod n^2 */
	bn_sqr(prv->crt->qi, prv->crt->n);					// n^2
    bn_add_dig(pub->g, prv->crt->n, 1);				// 1+n
    bn_mxp(prv->g, pub->g, prv->b, prv->crt->qi);	// (1+n)^b mod n^2
    bn_mxp(prv->gn, prv->g, prv->crt->n, prv->crt->qi);	// ((1+n)^b)^n mod n^2

	/* qInv = q^(-1) mod p. */
	bn_mod_inv(prv->crt->qi, prv->crt->q, prv->crt->p);

	/* n=pq */
	bn_copy(pub->crt->n, prv->crt->n);
	bn_copy(pub->g, prv->g);

	return result;
}

/* Encryption is faster if private key is known */
int cp_shpe_enc_prv(bn_t c, bn_t m, shpe_t prv) {
	bn_t r, s;
	int result = RLC_OK;

	bn_null(r);
	bn_null(s);

	if (prv == NULL || prv->crt->n == NULL || bn_bits(m) > bn_bits(prv->crt->n)) {
		return RLC_ERR;
	}

	RLC_TRY {
		bn_new(r);
		bn_new(s);

		/* Generate r in Z_alpha^*. */
        bn_rand_mod(r, prv->a);
		/* For G=(1+n)^b, compute c = (G^m)(G^n)^r mod n^2
         *  which is also c = (1+n*b*m)(G^n)^r mod n^2.
         */
		bn_sqr(s, prv->crt->n);			// n^2
        bn_mxp(r, prv->gn, r, s);	// (G^n)^r
        bn_mul(c, prv->crt->n, m);		// n*m
        bn_mod(c, c, s);
        bn_mul(c, c, prv->b);		// b*n*m
        bn_add_dig(c, c, 1);		// 1+b*n*m
        bn_mod(c, c, s);
        bn_mul(c, c, r);			// (1+n*b*m)(G^n)^r
        bn_mod(c, c, s);

	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(r);
		bn_free(s);
	}

	return result;
}

int cp_shpe_enc(bn_t c, bn_t m, shpe_t pub) {
	bn_t r, s;
	int result = RLC_OK;

	bn_null(r);
	bn_null(s);

	if (pub == NULL || pub->crt->n == NULL ||
			bn_bits(m) > bn_bits(pub->crt->n)) {
		return RLC_ERR;
	}

	RLC_TRY {
		bn_new(r);
		bn_new(s);

		/* Generate r in Z_alpha^*. */
        bn_rand_mod(r, pub->crt->n);
		/* For G=(1+n)^b, compute c = G^(m+nr) mod n^2
         */
		bn_sqr(s, pub->crt->n);
        bn_mul(r, r, pub->crt->n);		// n*r
        bn_add(r, r, m);			// m+n*r
        bn_mxp(c, pub->g, r, s);	// G^(m+n*r) mod n^2

	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(r);
		bn_free(s);
	}

	return result;
}

int cp_shpe_dec(bn_t m, bn_t c, shpe_t prv) {
	bn_t s, u;
	int result = RLC_OK;

	if (prv == NULL || bn_bits(c) > 2 * bn_bits(prv->crt->n)) {
		return RLC_ERR;
	}

	bn_null(s);
	bn_null(u);

	RLC_TRY {
		bn_new(s);
		bn_new(u);


#if MULTI == OPENMP
		omp_set_num_threads(CORES);
		#pragma omp parallel copyin(core_ctx) firstprivate(c, prv)
		{
			#pragma omp sections
			{
				#pragma omp section
				{
#endif
					/* Compute m_p = L(c^alpha mod p^2) * dp mod p. */
					bn_sqr(s, prv->crt->p);
					bn_mxp(s, c, prv->a, s);
					bn_sub_dig(s, s, 1);
					bn_div(s, s, prv->crt->p);
					bn_mul(s, s, prv->crt->dp);
					bn_mod(s, s, prv->crt->p);
#if MULTI == OPENMP
				}
				#pragma omp section
				{
#endif
					/* Compute m_q = (c^alpha mod q^2) * dq mod q. */
					bn_sqr(u, prv->crt->q);
					bn_mxp(u, c, prv->a, u);
					bn_sub_dig(u, u, 1);
					bn_div(u, u, prv->crt->q);
					bn_mul(u, u, prv->crt->dq);
					bn_mod(u, u, prv->crt->q);
#if MULTI == OPENMP
				}
			}
		}
#endif

		/* m = (m_p - m_q) mod p. */
		bn_sub(m, s, u);
		while (bn_sign(m) == RLC_NEG) {
			bn_add(m, m, prv->crt->p);
		}
		bn_mod(m, m, prv->crt->p);
		/* m1 = qInv(m_p - m_q) mod p. */
		bn_mul(m, m, prv->crt->qi);
		bn_mod(m, m, prv->crt->p);
		/* m = m2 + m1 * q. */
		bn_mul(m, m, prv->crt->q);
		bn_add(m, m, u);
		bn_mod(m, m, prv->crt->n);
	} RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(s);
		bn_free(u);
	}

	return result;
}
