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
 * Implementation of the hashing to class group.
 *
 * @ingroup qf
 */

#include "relic_core.h"
#include "relic_bn.h"
#include "relic_qf.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void qf_map(qf_t r, const uint8_t *msg, size_t len, const bn_t dsc,
		size_t bits) {
	bn_t p, b, t;
	uint32_t k = 0;
 
	bn_null(p);
	bn_null(b);
	bn_null(t);
 
	RLC_TRY {
		bn_new(p);
		bn_new(b);
		bn_new(t);
 
		while (1) {
			/*
			 * The prime comes from bn_map_prime, which owns the counter and the
			 * rejection. Resuming from the next one keeps both conditions,
			 * primality and the discriminant splitting, on a single sequence of
			 * candidates rather than restarting the search each time.
			 */
			if (bn_map_prime(p, &k, msg, len, bits, k) != RLC_OK) {
				RLC_THROW(ERR_NO_VALID);
			}
			k++;
 
			/* a form of this norm exists only when the discriminant splits */
			bn_mod(t, dsc, p);
			if (bn_smb_jac(t, p) != 1) {
				continue;
			}
			if (!bn_srt_mod(b, t, p)) {
				continue;
			}
			/*
			 * Both roots give a form, so one is chosen by a rule depending only
			 * on the prime, which keeps the function deterministic.
			 */
			{
				dig_t s3;
				bn_mod_dig(&s3, p, 3);
				if (s3 == 2) {
					bn_sub(b, p, b);
				}
			}
			/* the parity of b must match that of the discriminant, so that the
			 * root lifts from modulo p to modulo four p */
			if (bn_is_even(b) != bn_is_even(dsc)) {
				bn_sub(b, p, b);
			}
			qf_set_dsc(r, p, b, dsc);
			if (qf_has_dsc(r, dsc)) {
				qf_rdc(r, r);
				break;
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(p);
		bn_free(b);
		bn_free(t);
	}
}