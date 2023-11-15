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
 * Implementation of exponentiation in pairing groups.
 *
 * @ingroup pc
 */

#include "relic_pc.h"
#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void g1_mul(g1_t c, const g1_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		g1_mul_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			g1_neg(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G1_LOWER, mul)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g1_mul_gen(g1_t c, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G1_LOWER, mul_gen)(c, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul(g2_t c, const g2_t a, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	if (bn_bits(b) <= RLC_DIG) {
		g2_mul_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			g2_neg(c, c);
		}
		return;
	}

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G2_LOWER, mul)(c, a, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void g2_mul_gen(g2_t c, const bn_t b) {
	bn_t n, _b;

	bn_null(n);
	bn_null(_b);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);

		pc_get_ord(n);
		bn_mod(_b, b, n);

		RLC_CAT(RLC_G2_LOWER, mul_gen)(c, _b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
	}
}

void gt_exp(gt_t c, const gt_t a, const bn_t b) {
	if (bn_bits(b) <= RLC_DIG) {
		gt_exp_dig(c, a, b->dp[0]);
		if (bn_sign(b) == RLC_NEG) {
			gt_inv(c, c);
		}
		return;
	}

#if FP_PRIME < 1536
	RLC_CAT(RLC_GT_LOWER, exp_cyc_gls)(c, a, b);
#elif FP_PRIME == 1536
	RLC_CAT(RLC_GT_LOWER, exp_cyc)(c, a, b);
#else
	RLC_CAT(RLC_GT_LOWER, exp)(c, a, b);
#endif
}

void gt_exp_dig(gt_t c, const gt_t a, dig_t b) {
	gt_t s, t;
	bn_t _b;
	int8_t u, naf[RLC_DIG + 1];
	size_t l;

	if (b == 0) {
		gt_set_unity(c);
		return;
	}

	gt_null(s);
	gt_null(t);
	bn_null(_b);

	RLC_TRY {
		gt_new(s);
		gt_new(t);
		bn_new(_b);

		bn_set_dig(_b, b);

		l = RLC_DIG + 1;
		bn_rec_naf(naf, &l, _b, 2);

		gt_inv(s, a);
		gt_copy(t, a);
		for (int i = l - 2; i >= 0; i--) {
			gt_sqr(t, t);
			u = naf[i];
			if (u > 0) {
				gt_mul(t, t, a);
			} else if (u < 0) {
				gt_mul(t, t, s);
			}
		}

		gt_copy(c, t);
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		gt_free(s);
		gt_free(t);
		bn_free(_b);
	}
}

void gt_exp_sim(gt_t e, const gt_t a, const bn_t b, const gt_t c, const bn_t d) {
	bn_t n, _b, _d;
	gt_t t;

	bn_null(n);
	bn_null(_b);
	bn_null(_d);
	gt_null(t);

	RLC_TRY {
		bn_new(n);
		bn_new(_b);
		bn_new(_d);
		gt_new(t);

		gt_get_ord(n);
		bn_mod(_b, b, n);
		bn_mod(_d, d, n);

#if FP_PRIME <= 1536
		RLC_CAT(RLC_GT_LOWER, exp_cyc_sim)(e, a, _b, c, _d);
		(void)t;
#else
		gt_exp(t, a, _b);
		gt_exp(e, c, _d);
		gt_mul(e, e, t);
#endif
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(n);
		bn_free(_b);
		bn_free(_d);
		gt_free(t);
	}
}

void gt_exp_gen(gt_t c, const bn_t b) {
	gt_t g;

	gt_null(g);

	RLC_TRY {
		gt_new(g);

		gt_get_gen(g);
		gt_exp(c, g, b);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		gt_free(g);
	}
}
