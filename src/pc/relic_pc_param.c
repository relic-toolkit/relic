/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2020 RELIC Authors
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
 * Implementation parameter management for pairing-based protocols.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int pc_param_set_any(void) {
#if defined(EP_SUPER) && FP_PRIME == 382
	ep4_curve_set_super();
	return RLC_OK;
#else
	if (ep_param_set_any_pairf() != RLC_ERR) {
		return RLC_OK;
	}
#endif
	return RLC_ERR;
}

void pc_param_print(void) {
#if defined(EP_SUPER) && FP_PRIME == 382
	util_banner("Curve SS3-P382:", 0);
#else
	ep_param_print();
#endif
}

 int pc_param_level(void) {
	return ep_param_level();
 }

