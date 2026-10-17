/*
 * Copyright 2007-2009 RELIC Project
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file.
 *
 * RELIC is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of the low-level prime field reduction functions.
 *
 * @ingroup bn
 */

#include "relic_fp.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Reduces modulo the SECG Koblitz prime of the configured size.
 */
void fp_rdcs_k1_low(dig_t *c, const dig_t *a, const dig_t *m);

/**
 * Reduces modulo the SECG/NIST random-curve prime of the configured size.
 */
void fp_rdcs_p1_low(dig_t *c, const dig_t *a, const dig_t *m);

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void fp_rdcs_low(dig_t *c, const dig_t *a, const dig_t *m) {
	/* Only some primes have a reduction in assembly. */
	switch (fp_param_get()) {
#if FP_PRIME == 160 || FP_PRIME == 256
#if FP_PRIME == 160
		case SECG_160D:
#else
		case SECG_256:
#endif
			fp_rdcs_k1_low(c, a, m);
			break;
#if FP_PRIME == 160
		case SECG_160:
#else
		case NIST_256:
#endif
			fp_rdcs_p1_low(c, a, m);
			break;
#endif
		default:
			fp_rdc_quick(c, (dig_t *)a);
			break;
	}
}
