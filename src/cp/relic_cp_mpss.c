/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Implementation of the Pointcheval-Sanders signature protocols.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_mpss_gen(bn_t q[2], bn_t s[2], g2_t g, g2_t x[2], g2_t y[2]) {
	bn_t n;
	int result = RLC_OK;

	bn_null(n);

	TRY {
		bn_new(n);

		/* Generate keys for PS and secret share them. */
		g2_rand(g);
		g2_get_ord(n);

		bn_rand_mod(q[0], n);
		g2_mul(x[0], g, q[0]);
		bn_rand_mod(q[1], n);
		bn_sub(q[0], q[0], q[1]);
		g2_rand(x[1]);
		g2_sub(x[0], x[0], x[1]);
		g2_norm(x[0], x[0]);

		bn_rand_mod(s[0], n);
		g2_mul(y[0], g, s[0]);
		bn_rand_mod(s[1], n);
		bn_sub(s[0], s[0], s[1]);
		g2_rand(y[1]);
		g2_sub(y[0], y[0], y[1]);
		g2_norm(y[0], y[0]);
	}
	CATCH_ANY {
		result = RLC_ERR;
	}
	FINALLY {
		bn_free(n);
	}
	return result;
}

int cp_mpss_sig(g1_t b, g1_t a, bn_t m, bn_t r, bn_t s) {
	bn_t t, n;
	int result = RLC_OK;

	bn_null(t);
	bn_null(n);

	TRY {
		bn_new(t);
		bn_new(n);

		/* Same as the PS signature scheme, but random G1 generator comes from
		 * the outside. */
		g1_get_ord(n);
		bn_mul(t, m, s);
		bn_mod(t, t, n);
		bn_add(t, t, r);
		bn_mod(t, t, n);
		g1_mul(b, a, t);
	}
	CATCH_ANY {
		result = RLC_ERR;
	}
	FINALLY {
		bn_free(t);
		bn_free(n);
	}
	return result;
}

int cp_mpss_lcl(g1_t d, g2_t e, g1_t a, bn_t m, g2_t x, g2_t y, pt_t t) {
	g2_t q;
	int result = RLC_OK;

	g2_null(q);

	TRY {
		g2_new(q);
		gt_new(s);

		if (g1_is_infty(a)) {
			result = RLC_ERR;
		}

		g2_mul(q, y, m);
		g2_add(q, q, x);
		g2_norm(q, q);
		g2_neg(q, q);

		pc_map_lcl(d, e, a, q, t);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		g2_free(q);
	}
	return result;
}

int cp_mpss_ofv(gt_t r, g1_t a, g1_t b, bn_t m, g2_t g, g2_t x, g2_t y, pt_t t, g1_t d, g2_t e, int party) {
	g2_t q;
	gt_t s;
	int result = RLC_OK;

	g2_null(q);
	gt_null(s);

	TRY {
		g2_new(q);
		gt_new(s);

		if (g1_is_infty(a)) {
			result = RLC_ERR;
		}

		g2_mul(q, y, m);
		g2_add(q, q, x);
		g2_norm(q, q);
		g2_neg(q, q);

		pc_map_mpc(r, a, q, t, d, e, party);
		pc_map(s, b, g);
		gt_mul(r, r, s);
	}
	CATCH_ANY {
		THROW(ERR_CAUGHT);
	}
	FINALLY {
		g2_free(q);
		gt_free(s);
	}
	return result;
}

int cp_mpss_onv(gt_t e1, gt_t e2) {
	gt_t t;
	int result = 0;

	gt_null(t);

	TRY {
		gt_new(t);

		gt_mul(t, e1, e2);
		if (gt_is_unity(t)) {
			result = 1;
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		gt_free(t);
	}

	return result;
}
