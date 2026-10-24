/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of pairings with the generator of G_2.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void pc_map_gen(gt_t r, const g1_t p) {
#ifdef RLC_PC_GEN
	pc_map_fix(r, p, core_get()->g2_tab);
#else
	g2_t q;

	g2_null(q);

	RLC_TRY {
		g2_new(q);
		g2_get_gen(q);
		pc_map(r, p, q);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		g2_free(q);
	}
#endif
}

void pc_map_sim_gen(gt_t r, const g1_t *p, const g2_t *q, int m,
		const g1_t s) {
#ifdef RLC_PC_GEN
	const RLC_CAT(RLC_PC_FIELD, t) *t = core_get()->g2_tab;
	g1_t _s[1];

	g1_null(_s[0]);

	RLC_TRY {
		g1_new(_s[0]);
		g1_copy(_s[0], s);
		pc_map_sim_fix(r, p, q, m, _s, &t, 1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		g1_free(_s[0]);
	}
#else
	/* One more element, for the generator. */
	g1_t *_p = RLC_ALLOCA(g1_t, m + 1);
	g2_t *_q = RLC_ALLOCA(g2_t, m + 1);
	int i;

	if (_p == NULL || _q == NULL) {
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	for (i = 0; i <= m; i++) {
		g1_null(_p[i]);
		g2_null(_q[i]);
	}

	RLC_TRY {
		for (i = 0; i <= m; i++) {
			g1_new(_p[i]);
			g2_new(_q[i]);
		}
		for (i = 0; i < m; i++) {
			g1_copy(_p[i], p[i]);
			g2_copy(_q[i], q[i]);
		}
		g1_copy(_p[m], s);
		g2_get_gen(_q[m]);
		pc_map_sim(r, _p, _q, m + 1);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i <= m; i++) {
			g1_free(_p[i]);
			g2_free(_q[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
	}
#endif
}
