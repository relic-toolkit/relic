/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2019 RELIC Authors
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
 * Implementation of pairing computation for curves with embedding degree 8.
 *
 * @ingroup pp
 */

#include "relic_core.h"
#include "relic_pp_tmpl.h"
#include "relic_pp.h"
#include "relic_util.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

TMPL_PP_MIL(8, ep2);

TMPL_PP_MIL_LIT(8, ep2);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_PP_MAP_TATEP(8, ep2);

TMPL_PP_MAP_SIM_TATEP(8, ep2);

TMPL_PP_MAP_WEILP(8, ep2);

TMPL_PP_MAP_SIM_WEILP(8, ep2);

void pp_map_oatep_k8(fp8_t r, const ep_t p, const ep2_t q) {
	ep_t _p[1];
	ep2_t t[1], _q[1];
	bn_t a;

	ep_null(_p[0]);
	ep2_null(_q[0]);
	ep2_null(t[0]);
	bn_null(a);

	RLC_TRY {
		ep_new(_p[0]);
		ep2_new(_q[0]);
		ep2_new(t[0]);
		bn_new(a);

		fp_prime_get_par(a);
		fp8_set_dig(r, 1);

		ep_norm(_p[0], p);
		ep2_norm(_q[0], q);

		if (!ep_is_infty(_p[0]) && !ep2_is_infty(_q[0])) {
			/* r = f_{a,Q}(P). */
			pp_mil_k8(r, t, _q, _p, 1, a);
			pp_exp_k8(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		ep_free(_p[0]);
		ep2_free(_q[0]);
		ep2_free(t[0]);
		bn_free(a);
	}
}

void pp_map_sim_oatep_k8(fp8_t r, const ep_t *p, const ep2_t *q, int m) {
	ep_t *_p = RLC_ALLOCA(ep_t, m);
	ep2_t *t = RLC_ALLOCA(ep2_t, m), *_q = RLC_ALLOCA(ep2_t, m);
	bn_t a;
	int i, j;

	if (_p == NULL || _q == NULL || t == NULL) {
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	bn_null(a);
	for (i = 0; i < m; i++) {
		ep_null(_p[i]);
		ep2_null(_q[i]);
		ep2_null(t[i]);
	}

	RLC_TRY {
		bn_new(a);
		for (i = 0; i < m; i++) {
			ep_new(_p[i]);
			ep2_new(_q[i]);
			ep2_new(t[i]);
		}

		j = 0;
		for (i = 0; i < m; i++) {
			if (!ep_is_infty(p[i]) && !ep2_is_infty(q[i])) {
				ep_norm(_p[j], p[i]);
				ep2_norm(_q[j++], q[i]);
			}
		}

		fp_prime_get_par(a);
		fp8_set_dig(r, 1);

		if (j > 0) {
			/* r = f_{a,Q}(P). */
			pp_mil_k8(r, t, _q, _p, j, a);
			pp_exp_k8(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(a);
		for (i = 0; i < m; i++) {
			ep_free(_p[i]);
			ep2_free(_q[i]);
			ep2_free(t[i]);
		}
		RLC_FREE(_p);
		RLC_FREE(_q);
		RLC_FREE(t);
	}
}
