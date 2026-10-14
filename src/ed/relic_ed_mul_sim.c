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
 * Implementation of simultaneous point multiplication on binary elliptic
 * curves.
 *
 * @ingroup ed
 */

#include "relic_core.h"
#include "relic_ep_mul_tmpl.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

TMPL_EC_MUL_SIM_PLAIN(ed, RLC_FP_BITS);

TMPL_EC_MUL_SIM_LOT_PLAIN(ed);

TMPL_EC_MUL_SIM_LOT_PIPPE(ed);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

TMPL_EP_MUL_SIM(ed, plain);

TMPL_EC_MUL_SIM_GEN(ed);

void ed_mul_sim_lot(ed_t r, const ed_t p[], const bn_t k[], int n) {
	if (n == 0) {
		ed_set_infty(r);
		return;
	}

	/* Buckets pay off once the points outnumber a few dozen. */
	if (n > 32) {
		ed_mul_sim_lot_pippe(r, p, k, n);
	} else {
		ed_mul_sim_lot_plain(r, p, k, n);
	}
}
