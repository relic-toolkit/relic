/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2010 RELIC Authors
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
 * Implementation of the Boneh-Lynn-Schacham short signature protocol.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_bls_gen(bn_t d, g2_t q) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	RLC_TRY {
		bn_new(n);

		pc_get_ord(n);
		bn_rand_mod(d, n);
		g2_mul_gen(q, d);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_bls_sig(g1_t s, const uint8_t *msg, size_t len, const bn_t d) {
	g1_t p;
	int result = RLC_OK;

	g1_null(p);

	RLC_TRY {
		g1_new(p);
		g1_map(p, msg, len);
		g1_mul_sec(s, p, d);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		g1_free(p);
	}
	return result;
}

int cp_bls_ver(const g1_t s, const uint8_t *msg, size_t len, const g2_t q) {
	g1_t p[2];
	g2_t r[2];
	gt_t e;
	int result = 0;

	g1_null(p[0]);
	g1_null(p[1]);
	g2_null(r[0]);
	g2_null(r[1]);
	gt_null(e);

	RLC_TRY {
		g1_new(p[0]);
		g1_new(p[1]);
		g2_new(r[0]);
		g2_new(r[1]);
		gt_new(e);

		g1_map(p[0], msg, len);
		g1_copy(p[1], s);
		g2_copy(r[0], q);
		g2_get_gen(r[1]);
		g2_neg(r[1], r[1]);

		pc_map_sim(e, p, r, 2);
		if (gt_is_unity(e) && g2_is_valid(q)) {
			result = 1;
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		g1_free(p[0]);
		g1_free(p[1]);
		g2_free(r[0]);
		g2_free(r[1]);
		gt_free(e);
	}
	return result;
}

int cp_bls_agg_sig(g1_t sig, g2_t a, const g1_t s, const g2_t q) {
	bn_t t;
	g1_t u;
	g2_t p;
	uint8_t h[RLC_MD_LEN], *buf = RLC_ALLOCA(uint8_t, g2_size_bin(q, 0));
	int result = RLC_OK;

	bn_null(t);
	g1_null(u);
	g2_null(p);

	RLC_TRY {
		if (buf == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		bn_new(t);
		g1_new(u);
		g2_new(p);

		md_map(h, buf, g2_size_bin(q, 0));
		bn_read_bin(t, h, RLC_MIN(RLC_MD_LEN, RLC_CEIL(pc_param_level(), 8)));

		g1_mul(u, s, t);
		g1_add(sig, sig, u);

		g2_mul(p, q, t);
		g2_add(a, a, p);
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(t);
		g1_free(u);
		g2_free(p);
		RLC_FREE(buf);
	}
	return result;
}

int cp_bls_agg_ver(const g1_t s, const uint8_t **m, const size_t *l,
		size_t size, const g2_t q[]) {
	g1_t *p = RLC_ALLOCA(g1_t, size + 1);
	g2_t *r = RLC_ALLOCA(g2_t, size + 1);
	gt_t e;
	int result = 0;

	gt_null(e);

	RLC_TRY {
		if (p == NULL || r == NULL) {
			RLC_FREE(p);
			RLC_FREE(r);
			RLC_THROW(ERR_NO_MEMORY);
		}
		g1_null(p[0]);
		g2_null(r[0]);
		g1_new(p[0]);
		g2_new(r[0]);
		for (size_t i = 0; i < size; i++) {
			g1_null(p[i + 1]);
			g1_new(p[i + 1]);
			g2_null(r[i + 1]);
			g2_new(r[i + 1]);
			g1_map(p[i + 1], m[i], l[i]);
			g2_copy(r[i + 1], q[i]);
		}
		gt_new(e);

		g1_copy(p[0], s);
		g2_get_gen(r[0]);
		g2_neg(r[0], r[0]);

		pc_map_sim(e, p, r, size + 1);
		if (gt_is_unity(e)) {
			result = 1;
		}
		for (size_t i = 0; i < size; i++) {
			result = result & g2_is_valid(q[i]);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (size_t i = 0; i < size + 1; i++) {
			g1_free(p[i]);
			g2_free(r[i]);
		}
		gt_free(e);
		RLC_FREE(p);
		RLC_FREE(r);
	}
	return result;
}