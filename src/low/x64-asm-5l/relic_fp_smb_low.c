/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
 * Implementation of the low-level inversion functions.
 *
 * @&version $Id$
 * @ingroup fp
 */

#include <gmp.h>

#include "relic_fp.h"
#include "relic_fp_low.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp_smbm_low(const dig_t *a) {
	mpz_t n, p;
	rlc_align dig_t t[2 * RLC_FP_DIGS], u[RLC_FP_DIGS];
	int res;

	mpz_init(n);
	mpz_init(p);

#if FP_RDC == MONTY
	dv_zero(t + RLC_FP_DIGS, RLC_FP_DIGS);
	dv_copy(t, a, RLC_FP_DIGS);
	fp_rdcn_low(u, t);
#else
	fp_copy(u, a);
#endif

	mpz_import(n, RLC_FP_DIGS, -1, sizeof(dig_t), 0, 0, u);
	mpz_import(p, RLC_FP_DIGS, -1, sizeof(dig_t), 0, 0, fp_prime_get());

	res = mpz_jacobi(n, p);

	mpz_clear(n);
	mpz_clear(p);
	return res;
}
