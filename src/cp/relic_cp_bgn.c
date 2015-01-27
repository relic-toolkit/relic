/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2014 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of Freeman's prime-order version of the Boneh-Goh-Nissim
 * cryptosystem.
 *
 * @version $Id$
 * @ingroup cp
 */

#include <limits.h>

#include "relic_core.h"
#include "relic_conf.h"
#include "relic_rand.h"
#include "relic_bn.h"
#include "relic_util.h"
#include "relic_cp.h"
#include "relic_md.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_bgn_gen(bgn_t pub, bgn_t prv) {
	bn_t n;
	int result = STS_OK;

	bn_null(n);

	TRY {
		bn_new(n);

		g1_get_ord(n);

		do {
			bn_rand(prv->x, BN_POS, bn_bits(n));
			bn_mod(prv->x, prv->x, n);
		} while (bn_is_zero(prv->x));

		do {
			bn_rand(prv->y, BN_POS, bn_bits(n));
			bn_mod(prv->y, prv->y, n);
		} while (bn_is_zero(prv->y));

		do {
			bn_rand(prv->z, BN_POS, bn_bits(n));
			bn_mod(prv->z, prv->z, n);
		} while (bn_is_zero(prv->z));

		g1_rand(pub->g);
		g1_mul(pub->gx, pub->g, prv->x);
		g1_mul(pub->gy, pub->g, prv->y);
		g1_mul(pub->gz, pub->g, prv->z);
		g1_copy(prv->g, pub->g);

		g2_rand(pub->h);
		g2_mul(pub->hx, pub->h, prv->x);
		g2_mul(pub->hy, pub->h, prv->y);
		g2_mul(pub->hz, pub->h, prv->z);
		g2_copy(prv->h, pub->h);
	}
	CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		bn_free(n);
	}

	return result;
}

int cp_bgn_enc1(g1_t c0, g1_t c1, dig_t m, bgn_t pub) {
	bn_t r, n;
	g1_t t;
	int result = STS_OK;

	bn_null(n);
	bn_null(r);
	g1_null(t);

	TRY {
		bn_new(n);
		bn_new(r);
		g1_new(t);

		g1_get_ord(n);

		do {
			bn_rand(r, BN_POS, bn_bits(n));
			bn_mod(r, r, n);
		} while (bn_is_zero(r));

		/* Compute c0 = (ym + r)G. */
		g1_mul_dig(c0, pub->gy, m);
		g1_mul(t, pub->g, r);
		g1_add(c0, c0, t);
		/* Compute c0 = (zm + xr)G. */
		g1_mul_dig(c1, pub->gz, m);
		g1_mul(t, pub->gx, r);
		g1_add(c1, c1, t);
	}
	CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		bn_free(n);
		bn_free(r);
		g1_null(t);
	}

	return result;
}

int cp_bgn_dec1(dig_t *out, g1_t c0, g1_t c1, bgn_t prv) {
	bn_t r, n;
	g1_t s, t, u;
	int i, result = STS_OK;

	bn_null(r);
	g1_null(s);
	g1_null(t);
	g1_null(u);

	TRY {
		bn_new(r);
		g1_new(s);
		g1_new(t);
		g1_new(u);

		g1_get_ord(n);
		/* Compute T = x(ym + r)G - (zm + xr)G = m(xy - z)G. */
		g1_mul(t, c0, prv->x);
		g1_sub(t, t, c1);
		g1_norm(t, t);
		/* Compute U = (xy - z)G and find m. */
		bn_mul(r, prv->x, prv->y);
		bn_sub(r, r, prv->z);
		bn_mod(r, r, n);
		g1_mul(s, prv->g, r);
		g1_copy(u, s);
		for (i = 0; i < INT_MAX; i++) {
			if (g1_cmp(t, u) == CMP_EQ) {
				*out = i + 1;
				break;
			}
			g1_add(u, u, s);
			g1_norm(u, u);			
		}

		if (i == INT_MAX) {
			result = STS_ERR;
		}
	} CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		bn_free(r);
		g1_free(s);
		g1_free(t);
		g1_free(u);
	}

	return result;
}

int cp_bgn_enc2(g2_t c0, g2_t c1, dig_t m, bgn_t pub) {
	bn_t r, n;
	g2_t t;
	int result = STS_OK;

	bn_null(n);
	bn_null(r);
	g1_null(t);

	TRY {
		bn_new(n);
		bn_new(r);
		g1_new(t);

		g2_get_ord(n);

		do {
			bn_rand(r, BN_POS, bn_bits(n));
			bn_mod(r, r, n);
		} while (bn_is_zero(r));

		/* Compute c0 = (ym + r)G. */
		g2_mul_dig(c0, pub->hy, m);
		g2_mul(t, pub->h, r);
		g2_add(c0, c0, t);
		/* Compute c0 = (zm + xr)G. */
		g2_mul_dig(c1, pub->hz, m);
		g2_mul(t, pub->hx, r);
		g2_add(c1, c1, t);
	}
	CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		bn_free(n);
		bn_free(r);
		g1_free(t);
	}

	return result;
}

int cp_bgn_dec2(dig_t *m, g2_t c0, g2_t c1, bgn_t prv) {
	bn_t r, n;
	g2_t s, t, u;
	int i, result = STS_OK;

	bn_null(r);
	g2_null(s);
	g2_null(t);
	g2_null(u);

	TRY {
		bn_new(r);
		g2_new(s);
		g2_new(t);
		g2_new(u);

		g2_get_ord(n);
		/* Compute T = x(ym + r)G - (zm + xr)G = m(xy - z)G. */
		g2_mul(t, c0, prv->x);
		g2_sub(t, t, c1);
		g2_norm(t, t);
		/* Compute U = (xy - z)G and find m. */
		bn_mul(r, prv->x, prv->y);
		bn_sub(r, r, prv->z);
		bn_mod(r, r, n);
		g2_mul(s, prv->h, r);
		g2_copy(u, s);
		for (i = 0; i < INT_MAX; i++) {
			if (g2_cmp(t, u) == CMP_EQ) {
				*m = i + 1;
				break;
			}
			g2_add(u, u, s);
			g2_norm(u, u);			
		}

		if (i == INT_MAX) {
			result = STS_ERR;
		}
	} CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		bn_free(r);
		g2_free(s);
		g2_free(t);
		g2_free(u);
	}

	return result;
}
