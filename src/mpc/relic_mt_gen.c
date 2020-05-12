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
 * Implementation of multiplication tri generation.
 *
 * @ingroup mpc
 */

#include "relic_core.h"
#include "relic_bn.h"
#include "relic_mpc.h"
#include "relic_util.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void mt_gen(mt_t tri[2], bn_t order) {
	for (int i = 0; i < 2; i++) {
		bn_rand_mod(tri[i]->a, order);
		bn_rand_mod(tri[i]->b, order);
	}
	bn_add(tri[0]->c, tri[0]->a, tri[1]->a);
	bn_mod(tri[0]->c, tri[0]->c, order);
	bn_add(tri[1]->c, tri[0]->b, tri[1]->b);
	bn_mod(tri[1]->c, tri[1]->c, order);
	bn_mul(tri[0]->c, tri[0]->c, tri[1]->c);
	bn_mod(tri[0]->c, tri[0]->c, order);
	bn_rand_mod(tri[1]->c, order);
	bn_mod_inv(tri[1]->c, tri[1]->c, order);
	bn_mul(tri[0]->c, tri[0]->c, tri[1]->c);
	bn_mod_inv(tri[1]->c, tri[1]->c, order);
	bn_mod(tri[0]->c, tri[0]->c, order);
}
