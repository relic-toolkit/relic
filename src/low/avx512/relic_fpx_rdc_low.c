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
 * Implementation of the low-level extension field modular reduction in a
 * Residue Number System with AVX-512 IFMA, reducing the components together.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fp_rns_avx.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp2_rdcn_low(fp2_t c, dv2_t a) {
	dig_t *const cs[2] = { c[0], c[1] };
	const dig_t *const as[2] = { a[0], a[1] };

	rns_vrdc(cs, as, 2);
}

void fp3_rdcn_low(fp3_t c, dv3_t a) {
	dig_t *const cs[2] = { c[0], c[1] }, *const cs1[1] = { c[2] };
	const dig_t *const as[2] = { a[0], a[1] }, *const as1[1] = { a[2] };

	rns_vrdc(cs, as, 2);
	rns_vrdc(cs1, as1, 1);
}
