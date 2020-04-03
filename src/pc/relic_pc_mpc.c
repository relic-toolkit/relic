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
#include "relic_pc.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pc_map_tri(pt_t t[2]) {
	/* Generate a pairing triple. */
	g1_rand(t[0]->a);
	g2_rand(t[0]->b);
	pc_map(t[0]->c, t[0]->a, t[0]->b);

	/* Secret share the triple. */
	g1_rand(t[1]->a);
	g1_sub(t[0]->a, t[0]->a, t[1]->a);
	g1_norm(t[0]->a, t[0]->a);
	g2_rand(t[1]->b);
	g2_sub(t[0]->b, t[0]->b, t[1]->b);
	g2_norm(t[0]->b, t[0]->b);
	gt_rand(t[1]->c);
	gt_inv(t[1]->c, t[1]->c);
	gt_mul(t[0]->c, t[0]->c, t[1]->c);
	gt_inv(t[1]->c, t[1]->c);
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
