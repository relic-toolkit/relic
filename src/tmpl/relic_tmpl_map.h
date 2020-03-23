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
 * Templates for hashing to elliptic curves
 *
 * @ingroup tmpl
 */

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

#define TMPL_MAP_HORNER(TY_PFX, TY_IN)                                                   \
	static void TY_PFX##_eval(TY_PFX##_t c, TY_PFX##_t a, TY_IN *coeffs, int deg) {      \
		TY_PFX##_copy(c, coeffs[deg]);                                                   \
		for (int i = deg; i > 0; --i) {                                                  \
			TY_PFX##_mul(c, c, a);                                                       \
			TY_PFX##_add(c, c, coeffs[i - 1]);                                           \
		}                                                                                \
	}

#define TMPL_MAP_ISOGENY_MAP(ISONUM)                                                     \
	/* declaring this function inline suppresses "unused function" warnings */           \
	static inline void ep##ISONUM##_iso(ep##ISONUM##_t q, ep##ISONUM##_t p) {            \
		fp##ISONUM##_t t0, t1, t2, t3;                                                   \
                                                                                         \
		if (!ep##ISONUM##_curve_is_ctmap()) {                                            \
			ep##ISONUM##_copy(q, p);                                                     \
			return;                                                                      \
		}                                                                                \
		/* XXX need to add real support for input projective points */                   \
		if (!p->norm) {                                                                  \
			ep##ISONUM##_norm(p, p);                                                     \
		}                                                                                \
                                                                                         \
		fp##ISONUM##_null(t0);                                                           \
		fp##ISONUM##_null(t1);                                                           \
		fp##ISONUM##_null(t2);                                                           \
		fp##ISONUM##_null(t3);                                                           \
                                                                                         \
		TRY {                                                                            \
			fp##ISONUM##_new(t0);                                                        \
			fp##ISONUM##_new(t1);                                                        \
			fp##ISONUM##_new(t2);                                                        \
			fp##ISONUM##_new(t3);                                                        \
                                                                                         \
			iso##ISONUM##_t coeffs = ep##ISONUM##_curve_get_iso();                       \
                                                                                         \
			/* numerators */                                                             \
			fp##ISONUM##_eval(t0, p->x, coeffs->xn, coeffs->deg_xn);                     \
			fp##ISONUM##_eval(t1, p->x, coeffs->yn, coeffs->deg_yn);                     \
			/* denominators */                                                           \
			fp##ISONUM##_eval(t2, p->x, coeffs->yd, coeffs->deg_yd);                     \
			fp##ISONUM##_eval(t3, p->x, coeffs->xd, coeffs->deg_xd);                     \
                                                                                         \
			/* Y = Ny * Dx * Z^2. */                                                     \
			fp##ISONUM##_mul(q->y, p->y, t1);                                            \
			fp##ISONUM##_mul(q->y, q->y, t3);                                            \
			/* Z = Dx * Dy, t1 = Z^2. */                                                 \
			fp##ISONUM##_mul(q->z, t2, t3);                                              \
			fp##ISONUM##_sqr(t1, q->z);                                                  \
			fp##ISONUM##_mul(q->y, q->y, t1);                                            \
			/* X = Nx * Dy * Z. */                                                       \
			fp##ISONUM##_mul(q->x, t0, t2);                                              \
			fp##ISONUM##_mul(q->x, q->x, q->z);                                          \
			q->norm = 0;                                                                 \
		}                                                                                \
		CATCH_ANY { THROW(ERR_CAUGHT); }                                                 \
		FINALLY {                                                                        \
			fp##ISONUM##_free(t0);                                                       \
			fp##ISONUM##_free(t1);                                                       \
			fp##ISONUM##_free(t2);                                                       \
			fp##ISONUM##_free(t3);                                                       \
		}                                                                                \
	}
