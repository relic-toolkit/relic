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
 * Implementation of multiplication in a quartic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"
#include "relic_fpx_mul_tmpl.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

TMPL_FPX_MUL_QUAD(fp4, fp2, fp2_mul_nor);

#endif

#if PP_EXT == LAZYR || !defined(STRIP)

TMPL_FPX_MUL_UNR_QUAD(fp4, fp2, dv4, dv2, fp2, dv2, 1, 1,
		fp2_muln_low);

TMPL_FPX_MUL_LAZYR(fp4, dv4, fp2, dv2, 2);

#endif

TMPL_FPX_MUL_ART_QUAD(fp4, fp2, fp2_mul_nor);

void fp4_mul_frb(fp4_t c, const fp4_t a, int i, int j) {
	fp2_t t;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp_copy(t[0], core_get()->fp4_p1[0]);
		fp_copy(t[1], core_get()->fp4_p1[1]);

	    if (i == 1) {
			fp4_copy(c, a);
			for (int k = 0; k < j; k++) {
	        	fp2_mul(c[0], c[0], t);
				fp2_mul(c[1], c[1], t);
				if (ep_curve_is_pairf() == EP_FM16) {
					/* TODO: fix this ugly hack. */
					fp4_mul_art(c, c);
				}
				/* If constant in base field, then second component is zero. */
				if (core_get()->frb4 == 1) {
					fp4_mul_art(c, c);
					if (fp_prime_get_mod18() % 3 == 2) {
						fp4_mul_art(c, c);
					}
				}
			}
	    } else {
			RLC_THROW(ERR_NO_VALID);
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t);
	}
}

void fp4_mul_dig(fp4_t c, const fp4_t a, dig_t b) {
	fp2_mul_dig(c[0], a[0], b);
	fp2_mul_dig(c[1], a[1], b);
}
