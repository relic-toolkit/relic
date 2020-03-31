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

/**
 * Evaluate a polynomial represented by its coefficients over a using Horner's
 * rule. Might promove to an API if needed elsewhere in the future.
 */
#define TMPL_MAP_HORNER(TY_PFX, TY_IN)                                                   \
	static void TY_PFX##_eval(TY_PFX##_t c, TY_PFX##_t a, TY_IN *coeffs, int deg) {      \
		TY_PFX##_copy(c, coeffs[deg]);                                                   \
		for (int i = deg; i > 0; --i) {                                                  \
			TY_PFX##_mul(c, c, a);                                                       \
			TY_PFX##_add(c, c, coeffs[i - 1]);                                           \
		}                                                                                \
	}

/* conditionally normalize result of isogeny map when not using projective coords */
#if EP_ADD == PROJC
#define TMPL_MAP_ISOMAP_NORM(EXTDEG)                                                     \
	do {                                                                                 \
		/* Y = Ny * Dx * Z^2. */                                                         \
		fp##EXTDEG##_mul(q->y, p->y, t1);                                                \
		fp##EXTDEG##_mul(q->y, q->y, t3);                                                \
		/* Z = Dx * Dy, t1 = Z^2. */                                                     \
		fp##EXTDEG##_mul(q->z, t2, t3);                                                  \
		fp##EXTDEG##_sqr(t1, q->z);                                                      \
		fp##EXTDEG##_mul(q->y, q->y, t1);                                                \
		/* X = Nx * Dy * Z. */                                                           \
		fp##EXTDEG##_mul(q->x, t0, t2);                                                  \
		fp##EXTDEG##_mul(q->x, q->x, q->z);                                              \
		q->norm = 0;                                                                     \
	} while (0)
#else
#define TMPL_MAP_ISOMAP_NORM(EXTDEG)                                                     \
	do {                                                                                 \
		/* when working with affine coordinates, clear denominator */                    \
		fp##EXTDEG##_mul(q->z, t2, t3);                                                  \
		fp##EXTDEG##_inv(q->z, q->z);                                                    \
		/* y coord */                                                                    \
		fp##EXTDEG##_mul(q->y, p->y, q->z);                                              \
		fp##EXTDEG##_mul(q->y, q->y, t3);                                                \
		fp##EXTDEG##_mul(q->y, q->y, t1);                                                \
		/* x coord */                                                                    \
		fp##EXTDEG##_mul(q->x, t2, q->z);                                                \
		fp##EXTDEG##_mul(q->x, q->x, t0);                                                \
		/* z coord == 1 */                                                               \
		fp##EXTDEG##_set_dig(q->z, 1);                                                   \
		q->norm = 1;                                                                     \
	} while (0)
#endif

/**
 * Generic isogeny map evaluation for use with SSWU map.
 */
#define TMPL_MAP_ISOGENY_MAP(EXTDEG)                                                     \
	/* declaring this function inline suppresses "unused function" warnings */           \
	static inline void ep##EXTDEG##_iso(ep##EXTDEG##_t q, ep##EXTDEG##_t p) {            \
		fp##EXTDEG##_t t0, t1, t2, t3;                                                   \
                                                                                         \
		if (!ep##EXTDEG##_curve_is_ctmap()) {                                            \
			ep##EXTDEG##_copy(q, p);                                                     \
			return;                                                                      \
		}                                                                                \
		/* XXX need to add real support for input projective points */                   \
		if (!p->norm) {                                                                  \
			ep##EXTDEG##_norm(p, p);                                                     \
		}                                                                                \
                                                                                         \
		fp##EXTDEG##_null(t0);                                                           \
		fp##EXTDEG##_null(t1);                                                           \
		fp##EXTDEG##_null(t2);                                                           \
		fp##EXTDEG##_null(t3);                                                           \
                                                                                         \
		TRY {                                                                            \
			fp##EXTDEG##_new(t0);                                                        \
			fp##EXTDEG##_new(t1);                                                        \
			fp##EXTDEG##_new(t2);                                                        \
			fp##EXTDEG##_new(t3);                                                        \
                                                                                         \
			iso##EXTDEG##_t coeffs = ep##EXTDEG##_curve_get_iso();                       \
                                                                                         \
			/* numerators */                                                             \
			fp##EXTDEG##_eval(t0, p->x, coeffs->xn, coeffs->deg_xn);                     \
			fp##EXTDEG##_eval(t1, p->x, coeffs->yn, coeffs->deg_yn);                     \
			/* denominators */                                                           \
			fp##EXTDEG##_eval(t2, p->x, coeffs->yd, coeffs->deg_yd);                     \
			fp##EXTDEG##_eval(t3, p->x, coeffs->xd, coeffs->deg_xd);                     \
                                                                                         \
			/* normalize if necessary */                                                 \
			TMPL_MAP_ISOMAP_NORM(EXTDEG);                                                \
		}                                                                                \
		CATCH_ANY { THROW(ERR_CAUGHT); }                                                 \
		FINALLY {                                                                        \
			fp##EXTDEG##_free(t0);                                                       \
			fp##EXTDEG##_free(t1);                                                       \
			fp##EXTDEG##_free(t2);                                                       \
			fp##EXTDEG##_free(t3);                                                       \
		}                                                                                \
	}

/* Conditionally call isogeny mapping function depending on whether EP_CTMAP is defined */
#ifdef EP_CTMAP
#define TMPL_MAP_CALL_ISOMAP(EXTDEG,PT)                                                     \
	do {                                                                                 \
		if (ep##EXTDEG##_curve_is_ctmap()) {                                             \
			ep##EXTDEG##_iso(PT, PT);                                                      \
		}                                                                                \
	} while (0)
#else
#define TMPL_MAP_CALL_ISOMAP(EXTDEG,PT)  /* No isogeny map call in this case. */
#endif

/**
 * Simplified SWU mapping from Section 4 of
 * "Fast and simple constant-time hashing to the BLS12-381 Elliptic Curve"
 */
#define TMPL_MAP_SSWU(EXTDEG, PTR_TY, COPY_COND)                                                   \
	static void ep##EXTDEG##_map_sswu(ep##EXTDEG##_t p, fp##EXTDEG##_t t) {                        \
		fp##EXTDEG##_t t0, t1, t2, t3;                                                             \
		ctx_t *ctx = core_get();                                                                   \
		PTR_TY *mBoverA = ctx->ep##EXTDEG##_map_c[0];                                              \
		PTR_TY *a = ctx->ep##EXTDEG##_map_c[2];                                                    \
		PTR_TY *b = ctx->ep##EXTDEG##_map_c[3];                                                    \
		PTR_TY *u = ctx->ep##EXTDEG##_map_u;                                                       \
                                                                                                   \
		fp##EXTDEG##_null(t0);                                                                     \
		fp##EXTDEG##_null(t1);                                                                     \
		fp##EXTDEG##_null(t2);                                                                     \
		fp##EXTDEG##_null(t3);                                                                     \
                                                                                                   \
		TRY {                                                                                      \
			fp##EXTDEG##_new(t0);                                                                  \
			fp##EXTDEG##_new(t1);                                                                  \
			fp##EXTDEG##_new(t2);                                                                  \
			fp##EXTDEG##_new(t3);                                                                  \
                                                                                                   \
			/* start computing the map */                                                          \
			fp##EXTDEG##_sqr(t0, t);                                                               \
			fp##EXTDEG##_mul(t0, t0, u);  /* t0 = u * t^2 */                                       \
			fp##EXTDEG##_sqr(t1, t0);     /* t1 = u^2 * t^4 */                                     \
			fp##EXTDEG##_add(t2, t1, t0); /* t2 = u^2 * t^4 + u * t^2 */                           \
                                                                                                   \
			/* handle the exceptional cases */                                                     \
			/* XXX(rsw) should be done projectively */                                             \
			{                                                                                      \
				const int e1 = fp##EXTDEG##_is_zero(t2);                                           \
				fp##EXTDEG##_neg(t3, u);         /* t3 = -u */                                     \
				COPY_COND(t2, t3, e1);           /* exception: -u instead of u^2t^4 + ut^2 */      \
				fp##EXTDEG##_inv(t2, t2);        /* t2 = -1/u or 1/(u^2 * t^4 + u*t^2) */          \
				fp##EXTDEG##_add_dig(t3, t2, 1); /* t3 = 1 + t2 */                                 \
				COPY_COND(t2, t3, e1 == 0);      /* only add 1 if t2 != -1/u */                    \
			}                                                                                      \
			/* e1 goes out of scope */                                                             \
                                                                                                   \
			/* compute x1, g(x1) */                                                                \
			fp##EXTDEG##_mul(p->x, t2, mBoverA); /* -B / A * (1 + 1 / (u^2 * t^4 + u * t^2)) */    \
			fp##EXTDEG##_sqr(p->y, p->x);        /* x^2 */                                         \
			fp##EXTDEG##_add(p->y, p->y, a);     /* x^2 + a */                                     \
			fp##EXTDEG##_mul(p->y, p->y, p->x);  /* x^3 + a x */                                   \
			fp##EXTDEG##_add(p->y, p->y, b);     /* x^3 + a x + b */                               \
                                                                                                   \
			/* compute x2, g(x2) */                                                                \
			fp##EXTDEG##_mul(t2, t0, p->x); /* t2 = u * t^2 * x1 */                                \
			fp##EXTDEG##_mul(t1, t0, t1);   /* t1 = u^3 * t^6 */                                   \
			fp##EXTDEG##_mul(t3, t1, p->y); /* t5 = g(t2) = u^3 * t^6 * g(p->x) */                 \
                                                                                                   \
			/* XXX(rsw)                                                               */           \
			/* This should be done in constant time and without computing 2 sqrts.    */           \
			/* Avoiding a second sqrt relies on knowing the 2-adicity of the modulus. */           \
			if (!fp##EXTDEG##_srt(p->y, p->y)) {                                                   \
				/* try x2, g(x2) */                                                                \
				fp##EXTDEG##_copy(p->x, t2);                                                       \
				if (!fp##EXTDEG##_srt(p->y, t3)) {                                                 \
					THROW(ERR_NO_VALID);                                                           \
				}                                                                                  \
			}                                                                                      \
			fp##EXTDEG##_set_dig(p->z, 1);                                                         \
			p->norm = 1;                                                                           \
		}                                                                                          \
		CATCH_ANY { THROW(ERR_CAUGHT); }                                                           \
		FINALLY {                                                                                  \
			fp##EXTDEG##_free(t0);                                                                 \
			fp##EXTDEG##_free(t1);                                                                 \
			fp##EXTDEG##_free(t2);                                                                 \
			fp##EXTDEG##_free(t3);                                                                 \
		}                                                                                          \
	}

/**
 * Shallue--van de Woestijne map, based on the definition from
 * draft-irtf-cfrg-hash-to-curve-06, Section 6.6.1
 */
#define TMPL_MAP_SVDW(EXTDEG, PTR_TY, COPY_COND)                                                   \
	static void ep##EXTDEG##_map_svdw(ep##EXTDEG##_t p, fp##EXTDEG##_t t) {                        \
		fp##EXTDEG##_t t1, t2, t3, t4;                                                             \
		fp##EXTDEG##_null(t1);                                                                     \
		fp##EXTDEG##_null(t2);                                                                     \
		fp##EXTDEG##_null(t3);                                                                     \
		fp##EXTDEG##_null(t4);                                                                     \
                                                                                                   \
		TRY {                                                                                      \
			fp##EXTDEG##_new(t1);                                                                  \
			fp##EXTDEG##_new(t2);                                                                  \
			fp##EXTDEG##_new(t3);                                                                  \
			fp##EXTDEG##_new(t4);                                                                  \
                                                                                                   \
			ctx_t *ctx = core_get();                                                               \
			PTR_TY *gU = ctx->ep##EXTDEG##_map_c[0];                                               \
			PTR_TY *mUover2 = ctx->ep##EXTDEG##_map_c[1];                                          \
			PTR_TY *c3 = ctx->ep##EXTDEG##_map_c[2];                                               \
			PTR_TY *c4 = ctx->ep##EXTDEG##_map_c[3];                                               \
			PTR_TY *u = ctx->ep##EXTDEG##_map_u;                                                   \
                                                                                                   \
			/* start computing the map */                                                          \
			fp##EXTDEG##_sqr(t1, t);                                                               \
			fp##EXTDEG##_mul(t1, t1, gU);                                                          \
			fp##EXTDEG##_add_dig(t2, t1, 1); /* 1 + t^2 * g(u) */                                  \
			fp##EXTDEG##_sub_dig(t1, t1, 1);                                                       \
			fp##EXTDEG##_neg(t1, t1);     /* 1 - t^2 * g(u) */                                     \
			fp##EXTDEG##_mul(t3, t1, t2); /* (1 + t^2 * g(u)) * (1 - t^2 * g(u)) */                \
                                                                                                   \
			/* handle exceptional case */                                                          \
			{                                                                                      \
				/* compute inv0(t3), i.e., 0 if t3 == 0, 1/t3 otherwise */                         \
				const int e0 = fp##EXTDEG##_is_zero(t3);                                           \
				COPY_COND(t3, gU, e0); /* g(u) is guaranteed to be nonzero */                      \
				fp##EXTDEG##_inv(t3, t3);                                                          \
				fp##EXTDEG##_zero(t4);                                                             \
				COPY_COND(t3, t4, e0);                                                             \
			}                                                                                      \
			/* e0 goes out of scope */                                                             \
			fp##EXTDEG##_mul(t4, t, t1);                                                           \
			fp##EXTDEG##_mul(t4, t4, t3);                                                          \
			fp##EXTDEG##_mul(t4, t4, c3);                                                          \
                                                                                                   \
			/* XXX(rsw) this should be constant time */                                            \
			/* compute x1 and g(x1) */                                                             \
			fp##EXTDEG##_sub(p->x, mUover2, t4);                                                   \
			ep##EXTDEG##_rhs(p->y, p);                                                             \
			if (!fp##EXTDEG##_srt(p->y, p->y)) {                                                   \
				/* compute x2 and g(x2) */                                                         \
				fp##EXTDEG##_add(p->x, mUover2, t4);                                               \
				ep##EXTDEG##_rhs(p->y, p);                                                         \
				if (!fp##EXTDEG##_srt(p->y, p->y)) {                                               \
					/* compute x3 and g(x3) */                                                     \
					fp##EXTDEG##_sqr(p->x, t2);                                                    \
					fp##EXTDEG##_mul(p->x, p->x, t3);                                              \
					fp##EXTDEG##_sqr(p->x, p->x);                                                  \
					fp##EXTDEG##_mul(p->x, p->x, c4);                                              \
					fp##EXTDEG##_add(p->x, p->x, u);                                               \
					ep##EXTDEG##_rhs(p->y, p);                                                     \
					if (!fp##EXTDEG##_srt(p->y, p->y)) {                                           \
						THROW(ERR_NO_VALID);                                                       \
					}                                                                              \
				}                                                                                  \
			}                                                                                      \
			fp##EXTDEG##_set_dig(p->z, 1);                                                         \
			p->norm = 1;                                                                           \
		}                                                                                          \
		CATCH_ANY { THROW(ERR_CAUGHT); }                                                           \
		FINALLY {                                                                                  \
			fp##EXTDEG##_free(t1);                                                                 \
			fp##EXTDEG##_free(t2);                                                                 \
			fp##EXTDEG##_free(t3);                                                                 \
			fp##EXTDEG##_free(t4);                                                                 \
		}                                                                                          \
	}
