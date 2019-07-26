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
 * Implementation of squaring in a dodecic extension of a prime field.
 *
 * @ingroup fpx
 */

#include "relic_core.h"
#include "relic_fp_low.h"
#include "relic_fpx_low.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#if FPX_RDC == BASIC || !defined(STRIP)

void fp48_sqr_basic(fp48_t c, fp48_t a) {
	fp24_t t0, t1;

	fp24_null(t0);
	fp24_null(t1);

	TRY {
		fp24_new(t0);
		fp24_new(t1);

		fp24_add(t0, a[0], a[1]);
		fp24_mul_art(t1, a[1]);
		fp24_add(t1, a[0], t1);
		fp24_mul(t0, t0, t1);
		fp24_mul(c[1], a[0], a[1]);
		fp24_sub(c[0], t0, c[1]);
		fp24_mul_art(t1, c[1]);
		fp24_sub(c[0], c[0], t1);
		fp24_dbl(c[1], c[1]);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		fp24_free(t0);
		fp24_free(t1);
	}
}

void fp48_sqr_cyc_basic(fp48_t c, fp48_t a) {
	fp8_t t0, t1, t2, t3, t4, t5, t24;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);
	fp8_null(t3);
	fp8_null(t4);
	fp8_null(t5);
	fp8_null(t24);

	TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);
		fp8_new(t3);
		fp8_new(t4);
		fp8_new(t5);
		fp8_new(t24);

		/* Define z = sqrt(E) */

		/* Now a is seen as (t0,t1) + (t2,t3) * w + (t4,t5) * w^2 */

		/* (t0, t1) = (a00 + a11*z)^2. */
		fp8_sqr(t2, a[0][0]);
		fp8_sqr(t3, a[1][1]);
		fp8_add(t1, a[0][0], a[1][1]);

		fp8_mul_art(t0, t3);
		fp8_add(t0, t0, t2);

		fp8_sqr(t1, t1);
		fp8_sub(t1, t1, t2);
		fp8_sub(t1, t1, t3);

		fp8_sub(c[0][0], t0, a[0][0]);
		fp8_add(c[0][0], c[0][0], c[0][0]);
		fp8_add(c[0][0], t0, c[0][0]);

		fp8_add(c[1][1], t1, a[1][1]);
		fp8_add(c[1][1], c[1][1], c[1][1]);
		fp8_add(c[1][1], t1, c[1][1]);

		fp8_sqr(t0, a[0][1]);
		fp8_sqr(t1, a[1][2]);
		fp8_add(t5, a[0][1], a[1][2]);
		fp8_sqr(t2, t5);

		fp8_add(t3, t0, t1);
		fp8_sub(t5, t2, t3);

		fp8_add(t24, a[1][0], a[0][2]);
		fp8_sqr(t3, t24);
		fp8_sqr(t2, a[1][0]);

		fp8_mul_art(t24, t5);
		fp8_add(t5, t24, a[1][0]);
		fp8_dbl(t5, t5);
		fp8_add(c[1][0], t5, t24);

		fp8_mul_art(t4, t1);
		fp8_add(t5, t0, t4);
		fp8_sub(t24, t5, a[0][2]);

		fp8_sqr(t1, a[0][2]);

		fp8_dbl(t24, t24);
		fp8_add(c[0][2], t24, t5);

		fp8_mul_art(t4, t1);
		fp8_add(t5, t2, t4);
		fp8_sub(t24, t5, a[0][1]);
		fp8_dbl(t24, t24);
		fp8_add(c[0][1], t24, t5);

		fp8_add(t0, t2, t1);
		fp8_sub(t5, t3, t0);
		fp8_add(t24, t5, a[1][2]);
		fp8_dbl(t24, t24);
		fp8_add(c[1][2], t5, t24);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
		fp8_free(t3);
		fp8_free(t4);
		fp8_free(t5);
		fp8_free(t24);
	}
}

void fp48_sqr_pck_basic(fp48_t c, fp48_t a) {
	fp8_t t0, t1, t2, t3, t4, t5, t24;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);
	fp8_null(t3);
	fp8_null(t4);
	fp8_null(t5);
	fp8_null(t24);

	TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);
		fp8_new(t3);
		fp8_new(t4);
		fp8_new(t5);
		fp8_new(t24);

		fp8_sqr(t0, a[0][1]);
		fp8_sqr(t1, a[1][2]);
		fp8_add(t5, a[0][1], a[1][2]);
		fp8_sqr(t2, t5);

		fp8_add(t3, t0, t1);
		fp8_sub(t5, t2, t3);

		fp8_add(t24, a[1][0], a[0][2]);
		fp8_sqr(t3, t24);
		fp8_sqr(t2, a[1][0]);

		fp8_mul_art(t24, t5);
		fp8_add(t5, t24, a[1][0]);
		fp8_dbl(t5, t5);
		fp8_add(c[1][0], t5, t24);

		fp8_mul_art(t4, t1);
		fp8_add(t5, t0, t4);
		fp8_sub(t24, t5, a[0][2]);

		fp8_sqr(t1, a[0][2]);

		fp8_dbl(t24, t24);
		fp8_add(c[0][2], t24, t5);

		fp8_mul_art(t4, t1);
		fp8_add(t5, t2, t4);
		fp8_sub(t24, t5, a[0][1]);
		fp8_dbl(t24, t24);
		fp8_add(c[0][1], t24, t5);

		fp8_add(t0, t2, t1);
		fp8_sub(t5, t3, t0);
		fp8_add(t24, t5, a[1][2]);
		fp8_dbl(t24, t24);
		fp8_add(c[1][2], t5, t24);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
		fp8_free(t3);
		fp8_free(t4);
		fp8_free(t5);
		fp8_free(t24);
	}
}

#endif

#if FPX_RDC == LAZYR || !defined(STRIP)

void fp48_sqr_lazyr(fp48_t c, fp48_t a) {
	/* TODO: implement lazy reduction. */
	fp48_sqr_basic(c, a);
}

void fp48_sqr_cyc_lazyr(fp48_t c, fp48_t a) {
	fp8_t t0, t1, t2, t3, t4, t5, t24;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);
	fp8_null(t3);
	fp8_null(t4);
	fp8_null(t5);
	fp8_null(t24);

	TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);
		fp8_new(t3);
		fp8_new(t4);
		fp8_new(t5);
		fp8_new(t24);

		/* Define z = sqrt(E) */

		/* Now a is seen as (t0,t1) + (t2,t3) * w + (t4,t5) * w^2 */

		/* (t0, t1) = (a00 + a11*z)^2. */
		fp8_sqr(t2, a[0][0]);
		fp8_sqr(t3, a[1][1]);
		fp8_add(t1, a[0][0], a[1][1]);

		fp8_mul_art(t0, t3);
		fp8_add(t0, t0, t2);

		fp8_sqr(t1, t1);
		fp8_sub(t1, t1, t2);
		fp8_sub(t1, t1, t3);

		fp8_sub(c[0][0], t0, a[0][0]);
		fp8_add(c[0][0], c[0][0], c[0][0]);
		fp8_add(c[0][0], t0, c[0][0]);

		fp8_add(c[1][1], t1, a[1][1]);
		fp8_add(c[1][1], c[1][1], c[1][1]);
		fp8_add(c[1][1], t1, c[1][1]);

		fp8_sqr(t0, a[0][1]);
		fp8_sqr(t1, a[1][2]);
		fp8_add(t5, a[0][1], a[1][2]);
		fp8_sqr(t2, t5);

		fp8_add(t3, t0, t1);
		fp8_sub(t5, t2, t3);

		fp8_add(t24, a[1][0], a[0][2]);
		fp8_sqr(t3, t24);
		fp8_sqr(t2, a[1][0]);

		fp8_mul_art(t24, t5);
		fp8_add(t5, t24, a[1][0]);
		fp8_dbl(t5, t5);
		fp8_add(c[1][0], t5, t24);

		fp8_mul_art(t4, t1);
		fp8_add(t5, t0, t4);
		fp8_sub(t24, t5, a[0][2]);

		fp8_sqr(t1, a[0][2]);

		fp8_dbl(t24, t24);
		fp8_add(c[0][2], t24, t5);

		fp8_mul_art(t4, t1);
		fp8_add(t5, t2, t4);
		fp8_sub(t24, t5, a[0][1]);
		fp8_dbl(t24, t24);
		fp8_add(c[0][1], t24, t5);

		fp8_add(t0, t2, t1);
		fp8_sub(t5, t3, t0);
		fp8_add(t24, t5, a[1][2]);
		fp8_dbl(t24, t24);
		fp8_add(c[1][2], t5, t24);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
		fp8_free(t3);
		fp8_free(t4);
		fp8_free(t5);
		fp8_free(t24);
	}
}

void fp48_sqr_pck_lazyr(fp48_t c, fp48_t a) {
	fp8_t t0, t1, t2, t3, t4, t5, t24;

	fp8_null(t0);
	fp8_null(t1);
	fp8_null(t2);
	fp8_null(t3);
	fp8_null(t4);
	fp8_null(t5);
	fp8_null(t24);

	TRY {
		fp8_new(t0);
		fp8_new(t1);
		fp8_new(t2);
		fp8_new(t3);
		fp8_new(t4);
		fp8_new(t5);
		fp8_new(t24);

		fp8_sqr(t0, a[0][1]);
		fp8_sqr(t1, a[1][2]);
		fp8_add(t5, a[0][1], a[1][2]);
		fp8_sqr(t2, t5);

		fp8_add(t3, t0, t1);
		fp8_sub(t5, t2, t3);

		fp8_add(t24, a[1][0], a[0][2]);
		fp8_sqr(t3, t24);
		fp8_sqr(t2, a[1][0]);

		fp8_mul_art(t24, t5);
		fp8_add(t5, t24, a[1][0]);
		fp8_dbl(t5, t5);
		fp8_add(c[1][0], t5, t24);

		fp8_mul_art(t4, t1);
		fp8_add(t5, t0, t4);
		fp8_sub(t24, t5, a[0][2]);

		fp8_sqr(t1, a[0][2]);

		fp8_dbl(t24, t24);
		fp8_add(c[0][2], t24, t5);

		fp8_mul_art(t4, t1);
		fp8_add(t5, t2, t4);
		fp8_sub(t24, t5, a[0][1]);
		fp8_dbl(t24, t24);
		fp8_add(c[0][1], t24, t5);

		fp8_add(t0, t2, t1);
		fp8_sub(t5, t3, t0);
		fp8_add(t24, t5, a[1][2]);
		fp8_dbl(t24, t24);
		fp8_add(c[1][2], t5, t24);
	} CATCH_ANY {
		THROW(ERR_CAUGHT);
	} FINALLY {
		fp8_free(t0);
		fp8_free(t1);
		fp8_free(t2);
		fp8_free(t3);
		fp8_free(t4);
		fp8_free(t5);
		fp8_free(t24);
	}
}

#endif
