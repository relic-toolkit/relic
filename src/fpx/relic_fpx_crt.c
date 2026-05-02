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
 * Implementation of cube root in extensions defined over prime fields.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

void fp_luc(fp_t c, const fp_t a, const bn_t e) {
    fp_t v0, v1, v2;

	fp_null(v0);
	fp_null(v1);
	fp_null(v2);

	RLC_TRY {
    	fp_new(v0);
		fp_new(v1);
		fp_new(v2);
		
    	// v_0 = 2
    	fp_set_dig(v0, 2);

    	// v_1 = tau
    	fp_copy(v1, a);

		for (int i = bn_bits(e) - 1; i >= 0; i--) {
			fp_mul(v2, v0, v1);
			fp_sub(v2, v2, a);
			if (bn_get_bit(e, i)) {
				fp_sqr(v1, v1);
				fp_sub_dig(v1, v1, 2);
				fp_copy(v0, v2);
			} else {
				fp_sqr(v0, v0);
				fp_sub_dig(v0, v0, 2);
				fp_copy(v1, v2);
			}
		}
	    fp_copy(c, v0);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp_free(v0);
		fp_free(v1);
		fp_free(v2);
	}
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int fp2_is_cub(const fp2_t a) {
	fp2_t t;
	int r = 0;

	fp2_null(t);

	RLC_TRY {
		fp2_new(t);

		fp2_frb(t, a, 1);
		fp2_mul(t, t, a);
		r = fp_is_cub(t[0]);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		fp2_free(t);
	}

	return r;
}

int fp2_crt(fp2_t c, const fp2_t a) {
	int r = 0;
	bn_t d, e;
	fp2_t t, u;
#if ALLOC == AUTO	
	const dig_t *crt = (const dig_t *)fp_prime_get_crt();
#else
	const fp_t crt = (fp_t)fp_prime_get_crt();
#endif

	/* Algorithm from "Fast cube roots in Fp2 via the algebraic torus" by
	 * Youssef El Housni: https://eprint.iacr.org/2026/392.pdf */

	bn_null(d);
	bn_null(e);
	fp2_null(t);
	fp2_null(u);

	if (fp2_is_zero(a)) {
		fp2_zero(c);
		return 1;
	}

	RLC_TRY {
		bn_new(d);
		bn_new(e);
		fp2_new(t);
		fp2_new(u);

		if (fp_prime_get_mod18() % 3 == 1) {
			if (fp_is_zero(a[1])) {
				r = 1;
				fp_crt(c[0], a[0]);
				fp_zero(c[1]);
			} else if (fp_is_zero(a[0])) {
				r = 1;
#ifdef FP_QNRES
				fp_copy(t[1], a[1]);
#else
				fp_set_dig(t[0], -fp_prime_get_qnr());
				fp_inv(t[1], t[0]);
				fp_mul(t[1], t[1], a[1]);
#endif
				fp_neg(t[1], t[1]);
				fp_zero(c[0]);
				fp_crt(c[1], t[1]);
			} else {
				fp_sqr(t[0], a[0]);
				fp_sqr(t[1], a[1]);
				fp2_copy(u, t);
				for (int i = -1; i >= fp_prime_get_qnr(); i--) {
					fp_add(t[0], t[0], t[1]);
					fp_sub(u[0], u[0], u[1]);
				}
				fp_inv(t[1], t[0]);
				fp_crt(t[0], t[0]);
				fp_mul(u[0], u[0], t[1]);
				fp_dbl(u[0], u[0]);

				bn_set_dig(d, 3);
				e->used = RLC_FP_DIGS;
				dv_copy(e->dp, fp_prime_get(), RLC_FP_DIGS);
				bn_add_dig(e, e, 1);
				bn_mod_inv(d, d, e);
				fp_luc(u[0], u[0], d);

				fp_add_dig(u[1], u[0], 1);
				fp_mul(u[1], u[1], t[0]);
				fp_sub_dig(u[0], u[0], 1);
				fp_mul(u[0], u[0], t[0]);

				fp_mul(t[1], u[0], u[1]);
				fp_inv(t[1], t[1]);

				fp_mul(t[0], a[0], u[1]);
				fp_mul(t[0], t[0], t[1]);
				fp_mul(u[0], a[1], u[0]);
				fp_mul(t[1], u[0], t[1]);

				/* u = t^3, compare with a or correct if not equal. */
				fp2_sqr(u, t);
				fp2_mul(u, u, t);
				if (fp2_cmp(u, a) == RLC_EQ) {
					r = 1;
					fp2_copy(c, t);
				}
				
				if (fp_prime_get_mod18() % 9 == 1) {
					fp_mul(u[0], u[0], crt);
					fp_mul(u[0], u[0], crt);
					fp_mul(u[0], u[0], crt);
					fp_mul(u[1], u[1], crt);
					fp_mul(u[1], u[1], crt);
					fp_mul(u[1], u[1], crt);
					if (fp2_cmp(u, a) == RLC_EQ) {
						r = 1;
						fp_mul(c[0], t[0], crt);
						fp_mul(c[0], c[0], crt);
						fp_mul(c[1], t[1], crt);
						fp_mul(c[1], c[1], crt);
					} else {
						fp_mul(u[0], u[0], crt);
						fp_mul(u[0], u[0], crt);
						fp_mul(u[0], u[0], crt);
						fp_mul(u[1], u[1], crt);
						fp_mul(u[1], u[1], crt);
						fp_mul(u[1], u[1], crt);
						if (fp2_cmp(u, a) == RLC_EQ) {
							r = 1;
							fp_mul(c[0], t[0], crt);
							fp_mul(c[1], t[1], crt);
						}
					}
				}
			}
		} else {
			RLC_THROW(ERR_NO_VALID);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(d);
		bn_free(e);
		fp2_free(t);
		fp2_free(u);
	}
	return r;
}
