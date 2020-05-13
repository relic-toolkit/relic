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
 * Implementation of pairing triples for MPC applications.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_mpc.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void g1_mul_lcl(bn_t d, g1_t q, bn_t x, g1_t p, mt_t tri) {
	bn_t n;
	g1_t t;

	bn_null(n);
	g1_null(t);

	TRY {
		bn_new(n);
		g1_new(t);

		/* Compute public values for transmission. */
		g1_get_ord(n);
		bn_sub(d, x, tri->a);
		if (bn_sign(d) == RLC_NEG) {
			bn_add(d, d, n);
		}
		bn_mod(d, d, n);
		g1_mul_gen(t, tri->b);
		g1_sub(q, p, t);
		g1_norm(q, q);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
		g1_free(t);
	}
}

void g1_mul_bct(bn_t d[2], g1_t q[2]) {
	bn_t n;

	bn_null(n);

	TRY {
		bn_new(n);

		g1_get_ord(n);
		bn_add(d[0], d[0], d[1]);
		bn_mod(d[0], d[0], n);
		bn_copy(d[1], d[0]);
		g1_add(q[0], q[0], q[1]);
		g1_norm(q[0], q[0]);
		g1_copy(q[1], q[0]);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
	}
}

void g1_mul_mpc(g1_t r, bn_t x, g1_t p, mt_t tri, bn_t d, g1_t q, int party) {
	g1_t t;

	g1_null(t);

	TRY {
		g1_new(t);
		g1_new(u);

		if (party == 0) {
			g1_sub(t, p, q);
			g1_norm(t, t);
		} else {
			g1_copy(t, p);
		}
		g1_mul(r, q, x);
		g1_mul(t, t, d);
		g1_add(r, r, t);
		g1_mul_gen(t, tri->c);
		g1_add(r, r, t);
		g1_norm(r, r);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		g1_free(t);
	}
}

void g2_mul_lcl(bn_t d, g2_t q, bn_t x, g2_t p, mt_t tri) {
	bn_t n;
	g2_t t;

	bn_null(n);
	g2_null(t);

	TRY {
		bn_new(n);
		g2_new(t);

		/* Compute public values for transmission. */
		g2_get_ord(n);
		bn_sub(d, x, tri->a);
		if (bn_sign(d) == RLC_NEG) {
			bn_add(d, d, n);
		}
		bn_mod(d, d, n);
		g2_mul_gen(t, tri->b);
		g2_sub(q, p, t);
		g2_norm(q, q);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
		g2_free(t);
	}
}

void g2_mul_bct(bn_t d[2], g2_t q[2]) {
	bn_t n;

	bn_null(n);

	TRY {
		bn_new(n);

		g2_get_ord(n);
		bn_add(d[0], d[0], d[1]);
		bn_mod(d[0], d[0], n);
		bn_copy(d[1], d[0]);
		g2_add(q[0], q[0], q[1]);
		g2_norm(q[0], q[0]);
		g2_copy(q[1], q[0]);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
	}
}

void g2_mul_mpc(g2_t r, bn_t x, g2_t p, mt_t tri, bn_t d, g2_t q, int party) {
	g2_t t;

	g2_null(t);

	TRY {
		g2_new(t);
		g2_new(u);

		if (party == 0) {
			g2_sub(t, p, q);
			g2_norm(t, t);
		} else {
			g2_copy(t, p);
		}
		g2_mul(r, q, x);
		g2_mul(t, t, d);
		g2_add(r, r, t);
		g2_mul_gen(t, tri->c);
		g2_add(r, r, t);
		g2_norm(r, r);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		g2_free(t);
	}
}

void pc_map_tri(pt_t t[2]) {
	bn_t n;
	mt_t tri[2];

	bn_null(n);
	mt_null(tri[0]);
	mt_null(tri[1]);

	TRY {
		bn_new(n);
		mt_new(tri[0]);
		mt_new(tri[1]);

		g1_get_ord(n);
		mt_gen(tri, n);

		for (int i = 0; i < 2; i++) {
			g1_mul_gen(t[i]->a, tri[i]->a);
			g2_mul_gen(t[i]->b, tri[i]->b);
			gt_get_gen(t[i]->c);
			gt_exp(t[i]->c, t[i]->c, tri[i]->c);
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		bn_free(n);
		mt_free(t[0]);
		mt_free(t[1]);
	}
}

void pc_map_lcl(g1_t d, g2_t e, g1_t p, g2_t q, pt_t t) {
	/* Compute public values for transmission. */
	g1_sub(d, p, t->a);
	g1_norm(d, d);
	g2_sub(e, q, t->b);
	g2_norm(e, e);
}

void pc_map_bct(g1_t d[2], g2_t e[2]) {
	/* Add public values and replicate. */
	g1_add(d[0], d[0], d[1]);
	g1_norm(d[0], d[0]);
	g1_copy(d[1], d[0]);
	g2_add(e[0], e[0], e[1]);
	g2_norm(e[0], e[0]);
	g2_copy(e[1], e[0]);
}

void pc_map_mpc(gt_t r, g1_t p, g2_t q, pt_t triple, g1_t d, g2_t e, int party) {
	gt_t t;
	g1_t _p[2];
	g2_t _q[2];

	gt_null(t);

	TRY {
		gt_new(t);
		for (int i = 0; i < 2; i++) {
			g1_null(_p[i]);
			g2_null(_q[i]);
			g1_new(_p[i]);
			g2_new(_q[i]);
		}

		/* Compute the pairing in MPC. */
		if (party == 0) {
			g1_copy(_p[0], p);
			g2_copy(_q[0], e);
			g1_copy(_p[1], d);
			g2_sub(_q[1], q, e);
			g2_norm(_q[1], _q[1]);
			pc_map_sim(t, _p, _q, 2);
			gt_mul(r, triple->c, t);
		} else {
			g1_copy(_p[0], p);
			g2_copy(_q[0], e);
			g1_copy(_p[1], d);
			g2_copy(_q[1], q);
			pc_map_sim(t, _p, _q, 2);
			gt_mul(r, triple->c, t);
		}
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		gt_free(t);
		for (int i = 0; i < 2; i++) {
			g1_null(_p[i]);
			g2_null(_q[i]);
			g1_new(_p[i]);
			g2_new(_q[i]);
		}
	}
}
