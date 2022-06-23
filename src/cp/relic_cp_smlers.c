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
 * Implementation of extendable ring signatures.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_smlers_sig(bn_t td, smlers_t p, const uint8_t *msg, size_t len,
		const bn_t sk, const ec_t pk, const ec_t pp) {
	ec_t g[2], y[2];
	int result = RLC_OK;

	ec_null(g[0]);
	ec_null(g[1]);
	ec_null(y[0]);
	ec_null(y[1]);

	RLC_TRY {
		ec_new(g[0]);
		ec_new(g[1]);
		ec_new(y[0]);
		ec_new(y[1]);

		ec_curve_get_gen(g[0]);
		ec_map(g[1], msg, len);
		ec_mul(p->tau, g[1], sk);

		cp_ers_sig(td, p->sig, msg, len, sk, pk, pp);

		ec_copy(y[0], p->sig->h);
		ec_copy(y[1], p->tau);
		cp_sokor_sig(p->c, p->r, msg, len, y, g, sk, 0);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		ec_free(g[0]);
		ec_free(g[1]);
		ec_free(y[0]);
		ec_free(y[1]);
	}
	return result;
}

int cp_smlers_ver(bn_t td, smlers_t *s, size_t size, const uint8_t *msg,
		size_t len, const ec_t pp) {
	bn_t n;
	ec_t t, g[2], y[2];
	int flag = 0, result = 0;

	bn_null(n);
	ec_null(t);
	ec_null(g[0]);
	ec_null(g[1]);
	ec_null(y[0]);
	ec_null(y[1]);

	RLC_TRY {
		bn_new(n);
		ec_new(t);
		ec_new(g[0]);
		ec_new(g[1]);
		ec_new(y[0]);
		ec_new(y[1]);

		ec_curve_get_ord(n);
		ec_mul_gen(t, td);
		ec_curve_get_gen(g[0]);
		ec_map(g[1], msg, len);

		for (int i = 0; i < size; i++) {
            ec_add(t, t, s[i]->sig->h);
        }
		if (ec_cmp(pp, t) == RLC_EQ) {
			flag = 1;
			for (int i = 0; i < size; i++) {
				ec_copy(y[0], s[i]->sig->h);
				ec_copy(y[1], s[i]->sig->pk);
				flag &= cp_sokor_ver(s[i]->sig->c, s[i]->sig->r, msg, len, y, NULL);
				ec_copy(y[1], s[i]->tau);
				flag &= cp_sokor_ver(s[i]->c, s[i]->r, msg, len, y, g);
	        }
		}
		result = flag;
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(n);
		ec_free(t);
		ec_free(g[0]);
		ec_free(g[1]);
		ec_free(y[0]);
		ec_free(y[1]);
	}
	return result;
}

int cp_smlers_ext(bn_t td, smlers_t *p, size_t *size, const uint8_t *msg,
		size_t len, const ec_t pk, const ec_t pp) {
	bn_t n, r;
	ec_t g[2], y[2];
	int result = RLC_OK;

	bn_null(n);
	bn_null(r);
	ec_null(g[0]);
	ec_null(g[1]);
	ec_null(y[0]);
	ec_null(y[1]);

	for (int i = 0; i < *size; i++) {
		if (ec_cmp(pk, p[i]->sig->pk) == RLC_EQ) {
			return RLC_ERR;
		}
	}

	RLC_TRY {
		bn_new(n);
		bn_new(r);
		ec_new(g[0]);
		ec_new(g[1]);
		ec_new(y[0]);
		ec_new(y[1]);

		ec_curve_get_ord(n);
		bn_rand_mod(r, n);
		bn_sub(td, td, r);
		bn_mod(td, td, n);
		ec_mul_gen(p[*size]->sig->h, r);
		ec_curve_get_gen(g[0]);
		ec_map(g[1], msg, len);

		ec_copy(p[*size]->sig->pk, pk);
		ec_copy(y[0], p[*size]->sig->h);
		ec_copy(y[1], p[*size]->sig->pk);
		cp_sokor_sig(p[*size]->sig->c, p[*size]->sig->r, msg, len, y, NULL, r, 1);
		ec_copy(p[*size]->tau, p[*size - 1]->tau);
		ec_copy(y[1], p[*size]->tau);
		cp_sokor_sig(p[*size]->c, p[*size]->r, msg, len, y, g, r, 1);
		(*size)++;
		result = RLC_OK;
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
	}
	return result;
}
