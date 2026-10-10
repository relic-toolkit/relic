/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2024 RELIC Authors
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
 * Template for hashing to prime elliptic curves.
 *
 * @ingroup tmpl
 */

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Evaluates a polynomial represented by its coefficients over a using Horner's
 * rule. Might promove to an API if needed elsewhere in the future.
 */
#define TMPL_MAP_HORNER(PFX, IN)											\
	static void PFX##_eval(PFX##_t c, PFX##_t a, IN *coeffs, int deg) {		\
		PFX##_copy(c, coeffs[deg]);											\
		for (int i = deg; i > 0; --i) {										\
			PFX##_mul(c, c, a);												\
			PFX##_add(c, c, coeffs[i - 1]);									\
		}																	\
	}

/* conditionally normalize result of isogeny map when not using projective coords */
#if EP_ADD == JACOB

#define TMPL_MAP_ISOMAP_NORM(PFX)											\
	do {																	\
		/* Y = Ny * Dx * Z^2. */											\
		PFX##_mul(q->y, p->y, t1);											\
		PFX##_mul(q->y, q->y, t3);											\
		/* Z = Dx * Dy, t1 = Z^2. */										\
		PFX##_mul(q->z, t2, t3);											\
		PFX##_sqr(t1, q->z);												\
		PFX##_mul(q->y, q->y, t1);											\
		/* X = Nx * Dy * Z. */												\
		PFX##_mul(q->x, t0, t2);											\
		PFX##_mul(q->x, q->x, q->z);										\
		q->coord = JACOB;													\
	} while (0)																\

#elif EP_ADD == PROJC

#define TMPL_MAP_ISOMAP_NORM(PFX)											\
		/* Z = Dx * Dy. */													\
		PFX##_mul(q->z, t2, t3);											\
		/* X = Nx * Dy. */													\
		PFX##_mul(q->x, t0, t2);											\
		/* Y = Ny * Dx. */													\
		PFX##_mul(q->y, p->y, t1);											\
		PFX##_mul(q->y, q->y, t3);											\
		q->coord = PROJC;													\

#else

#define TMPL_MAP_ISOMAP_NORM(PFX)											\
	do {																	\
		/* when working with affine coordinates, clear denominator */		\
		PFX##_mul(q->z, t2, t3);											\
		PFX##_inv(q->z, q->z);												\
		/* y coord */														\
		PFX##_mul(q->y, p->y, q->z);										\
		PFX##_mul(q->y, q->y, t3);											\
		PFX##_mul(q->y, q->y, t1);											\
		/* x coord */														\
		PFX##_mul(q->x, t2, q->z);											\
		PFX##_mul(q->x, q->x, t0);											\
		/* z coord == 1 */													\
		PFX##_set_dig(q->z, 1);												\
		q->coord = BASIC;													\
	} while (0)																\

#endif

/**
 * Generic isogeny map evaluation for use with SSWU map.
 */
#define TMPL_MAP_ISOGENY_MAP(CUR, PFX, ISO)									\
	/* declaring this function inline suppresses unused warnings */			\
	static inline void CUR##_iso(CUR##_t q, CUR##_t p) {					\
		PFX##_t t0, t1, t2, t3;												\
																			\
		if (!CUR##_curve_is_ctmap()) {										\
			CUR##_copy(q, p);												\
			return;															\
		}																	\
		/* XXX need to add real support for input projective points */		\
		if (p->coord != BASIC) {											\
			CUR##_norm(p, p);												\
		}																	\
																			\
		PFX##_null(t0);														\
		PFX##_null(t1);														\
		PFX##_null(t2);														\
		PFX##_null(t3);														\
                                                                    		\
		RLC_TRY {															\
			PFX##_new(t0);													\
			PFX##_new(t1);													\
			PFX##_new(t2);													\
			PFX##_new(t3);													\
																			\
			ISO##_t coeffs = CUR##_curve_get_iso();							\
																			\
			/* numerators */												\
			PFX##_eval(t0, p->x, coeffs->xn, coeffs->deg_xn);				\
			PFX##_eval(t1, p->x, coeffs->yn, coeffs->deg_yn);				\
			/* denominators */												\
			PFX##_eval(t2, p->x, coeffs->yd, coeffs->deg_yd);				\
			PFX##_eval(t3, p->x, coeffs->xd, coeffs->deg_xd);				\
																			\
			/* normalize if necessary */									\
			TMPL_MAP_ISOMAP_NORM(PFX);										\
		}																	\
		RLC_CATCH_ANY { RLC_THROW(ERR_CAUGHT); }							\
		RLC_FINALLY {														\
			PFX##_free(t0);													\
			PFX##_free(t1);													\
			PFX##_free(t2);													\
			PFX##_free(t3);													\
		}																	\
	}																		\

/* Call the isogeny map if the curve has one. */
#define TMPL_MAP_CALL_ISOMAP(CUR, PT)										\
	do {																	\
		if (CUR##_curve_is_ctmap()) {										\
			CUR##_iso(PT, PT);												\
		}																	\
	} while (0)																\

/**
 * Simplified SWU mapping from Section 4 of
 * "Fast and simple constant-time hashing to the BLS12-381 Elliptic Curve"
 */
#define TMPL_MAP_SSWU(CUR, PFX, PTR_TY)										\
	static void CUR##_map_sswu(CUR##_t p, const PFX##_t t) {				\
		PFX##_t t0, t1, t2, t3;												\
		ctx_t *ctx = core_get();											\
		PTR_TY *mBoverA = ctx->CUR##_map_c[0];								\
		PTR_TY *a = ctx->CUR##_map_c[2];									\
		PTR_TY *b = ctx->CUR##_map_c[3];									\
		PTR_TY *u = ctx->CUR##_map_u;										\
                                                                            \
		PFX##_null(t0);														\
		PFX##_null(t1);														\
		PFX##_null(t2);														\
		PFX##_null(t3);														\
																			\
		RLC_TRY {															\
			PFX##_new(t0);													\
			PFX##_new(t1);													\
			PFX##_new(t2);													\
			PFX##_new(t3);													\
																			\
			/* start computing the map */									\
			PFX##_sqr(t0, t);												\
			PFX##_mul(t0, t0, u);  /* t0 = u * t^2 */						\
			PFX##_sqr(t1, t0);     /* t1 = u^2 * t^4 */						\
			PFX##_add(t2, t1, t0); /* t2 = u^2 * t^4 + u * t^2 */			\
																			\
			/* handle the exceptional cases */								\
			/* XXX(rsw) should be done projectively */						\
			{																\
				const int e1 = PFX##_is_zero(t2);							\
				PFX##_neg(t3, u);           /* t3 = -u */					\
				/* exception: -u instead of u^2t^4 + ut^2 */				\
				PFX##_copy_sec(t2, t3, e1);      							\
				/* t2 = -1/u or 1/(u^2 * t^4 + u*t^2) */					\
				PFX##_inv(t2, t2);          								\
				PFX##_add_dig(t3, t2, 1);   /* t3 = 1 + t2 */				\
				PFX##_copy_sec(t2, t3, e1 == 0); /* add 1 if t2 != -1/u */	\
			}																\
			/* e1 goes out of scope */										\
			/* compute x1, g(x1) */											\
			/* -B / A * (1 + 1 / (u^2 * t^4 + u * t^2)) */					\
			PFX##_mul(p->x, t2, mBoverA);									\
			PFX##_sqr(p->y, p->x);        /* x^2 */							\
			PFX##_add(p->y, p->y, a);     /* x^2 + a */						\
			PFX##_mul(p->y, p->y, p->x);  /* x^3 + a x */					\
			PFX##_add(p->y, p->y, b);     /* x^3 + a x + b */				\
                                                                            \
			/* compute x2, g(x2) */											\
			PFX##_mul(t2, t0, p->x); /* t2 = u * t^2 * x1 */				\
			PFX##_mul(t1, t0, t1);   /* t1 = u^3 * t^6 */					\
			PFX##_mul(t3, t1, p->y); /* t5 = g(t2) = u^3 * t^6 * g(p->x) */	\
			{																\
				/* try x2, g(x2) */											\
				const int e1 = PFX##_is_sqr(p->y);							\
				PFX##_copy_sec(p->x, t2, e1 == 0);							\
				PFX##_copy_sec(p->y, t3, e1 == 0);							\
			}																\
			if (!PFX##_srt(p->y, p->y)) {									\
				RLC_THROW(ERR_NO_VALID);									\
			}																\
			PFX##_set_dig(p->z, 1);											\
			p->coord = BASIC;												\
		}																	\
		RLC_CATCH_ANY { RLC_THROW(ERR_CAUGHT); }							\
		RLC_FINALLY {														\
			PFX##_free(t0);													\
			PFX##_free(t1);													\
			PFX##_free(t2);													\
			PFX##_free(t3);													\
		}																	\
	}																		\

/**
 * Shallue--van de Woestijne map, based on the definition from
 * draft-irtf-cfrg-hash-to-curve-06, Section 6.6.1
 */
#define TMPL_MAP_SVDW(CUR, PFX, PTR_TY)										\
	static void CUR##_map_svdw(CUR##_t p, const PFX##_t t) {				\
		PFX##_t t1, t2, t3, t4;												\
		ctx_t *ctx = core_get();											\
		PTR_TY *gU = ctx->CUR##_map_c[0];									\
		PTR_TY *mUover2 = ctx->CUR##_map_c[1];								\
		PTR_TY *c3 = ctx->CUR##_map_c[2];									\
		PTR_TY *c4 = ctx->CUR##_map_c[3];									\
		PTR_TY *u = ctx->CUR##_map_u;										\
																			\
		PFX##_null(t1);														\
		PFX##_null(t2);														\
		PFX##_null(t3);														\
		PFX##_null(t4);														\
                                                                            \
		RLC_TRY {															\
			PFX##_new(t1);													\
			PFX##_new(t2);													\
			PFX##_new(t3);													\
			PFX##_new(t4);													\
																			\
			/* start computing the map */									\
			PFX##_sqr(t1, t);												\
			PFX##_mul(t1, t1, gU);											\
			PFX##_add_dig(t2, t1, 1); /* 1 + t^2 * g(u) */					\
			PFX##_sub_dig(t1, t1, 1);										\
			PFX##_neg(t1, t1);     /* 1 - t^2 * g(u) */						\
			PFX##_mul(t3, t1, t2); /* (1+t^2*g(u)) * (1-t^2*g(u)) */		\
                                                                            \
			/* handle exceptional case */									\
			{																\
				/* compute inv0(t3), i.e., 0 if t3 == 0, 1/t3 otherwise */	\
				const int e0 = PFX##_is_zero(t3);							\
				PFX##_copy_sec(t3, gU, e0); /* g(u) is nonzero */			\
				PFX##_inv(t3, t3);											\
				PFX##_zero(t4);												\
				PFX##_copy_sec(t3, t4, e0);									\
			}																\
			/* e0 goes out of scope */										\
			PFX##_mul(t4, t, t1);											\
			PFX##_mul(t4, t4, t3);											\
			PFX##_mul(t4, t4, c3);											\
																			\
			/* compute x1 and g(x1) */										\
			PFX##_sub(p->x, mUover2, t4);									\
			CUR##_rhs(p->y, p->x);											\
			{																\
				const int e0 = PFX##_is_sqr(p->y);							\
				/* compute x2 and g(x2) */									\
				PFX##_add(t4, mUover2, t4);									\
				PFX##_copy_sec(p->x, t4, e0 == 0);							\
				CUR##_rhs(t1, p->x);										\
				PFX##_copy_sec(p->y, t1, e0 == 0);							\
			}																\
			{																\
				const int e1 = PFX##_is_sqr(p->y);							\
				/* compute x3 and g(x3) */									\
				PFX##_sqr(t1, t2);											\
				PFX##_mul(t1, t1, t3);										\
				PFX##_sqr(t1, t1);											\
				PFX##_mul(t1, t1, c4);										\
				PFX##_add(t1, t1, u);										\
				PFX##_copy_sec(p->x, t1, e1 == 0);							\
				CUR##_rhs(t2, p->x);										\
				PFX##_copy_sec(p->y, t2, e1 == 0);							\
			}																\
			if (!PFX##_srt(p->y, p->y)) {									\
				RLC_THROW(ERR_NO_VALID);									\
			}																\
			PFX##_set_dig(p->z, 1);											\
			p->coord = BASIC;												\
		}																	\
		RLC_CATCH_ANY { RLC_THROW(ERR_CAUGHT); }							\
		RLC_FINALLY {														\
			PFX##_free(t1);													\
			PFX##_free(t2);													\
			PFX##_free(t3);													\
			PFX##_free(t4);													\
		}																	\
	}																		\

/**
 * Flips a sign bit by the sign of an extension field element, defined as the
 * parity of its first nonzero coefficient, so that the square root chosen
 * from T and -T depends only on the sign bit.
 *
 * @param[in] F			- the field prefix.
 * @param[in] T			- the extension field element.
 * @param[in] K			- a temporary multiple precision integer.
 * @param[in,out] S		- the sign bit.
 */
#define TMPL_EP_MAP_SGN0(F, T, K, S)										\
	do {																	\
		uint8_t _done = 0, _bit = 0, _zero;									\
		for (int _i = 0; _i < (int)(sizeof(F##_t) / sizeof(fp_t)); _i++) {	\
			_zero = fp_is_zero(((fp_t *)T)[_i]);							\
			fp_prime_back(K, ((fp_t *)T)[_i]);								\
			_bit |= (~_done) & bn_get_bit(K, 0);							\
			_done |= !_zero;												\
		}																	\
		S ^= (_bit & 1);													\
	} while (0)

/**
 * Defines a template for hashing a message to two extension field elements
 * and a sign bit, the input of the maps to the curve.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MAP_INPUT(C, F)												\
	static uint8_t C##_map_input(F##_t u, F##_t t, const uint8_t *msg,		\
			size_t len) {													\
		/* Space for two field elements plus extra bytes for uniformity. */	\
		const int D = (int)(sizeof(F##_t) / sizeof(fp_t));					\
		const size_t elm = (FP_PRIME + ep_param_level() + 7) / 8;			\
		uint8_t sign = 0, *r = RLC_ALLOCA(uint8_t, 2 * D * elm + 1);		\
		bn_t k;																\
																			\
		bn_null(k);															\
																			\
		RLC_TRY {															\
			bn_new(k);														\
			if (r == NULL) {												\
				RLC_THROW(ERR_NO_MEMORY);									\
			}																\
			md_xmd(r, 2 * D * elm + 1, msg, len, (const uint8_t *)"RELIC", 5);\
			for (int i = 0; i < D; i++) {									\
				bn_read_bin(k, r + 2 * i * elm, elm);						\
				fp_prime_conv(((fp_t *)u)[i], k);							\
				bn_read_bin(k, r + (2 * i + 1) * elm, elm);					\
				fp_prime_conv(((fp_t *)t)[i], k);							\
			}																\
			sign = r[2 * D * elm] & 1;										\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(k);														\
			RLC_FREE(r);													\
		}																	\
		return sign;														\
	}

/**
 * Defines a template for mapping two extension field elements to an elliptic
 * curve with a = 0, combining three candidate abscissas so that one of them
 * yields a square.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MAP_A0(C, F)												\
	static void C##_map_a0(C##_t p, F##_t u, F##_t t, uint8_t sign) {		\
		F##_t v, w, y, x1, y1, z1;											\
		ctx_t *ctx = core_get();											\
		dig_t c2, c3;														\
		bn_t k;																\
																			\
		bn_null(k);															\
		F##_null(v);														\
		F##_null(w);														\
		F##_null(y);														\
		F##_null(x1);														\
		F##_null(y1);														\
		F##_null(z1);														\
																			\
		RLC_TRY {															\
			bn_new(k);														\
			F##_new(v);														\
			F##_new(w);														\
			F##_new(y);														\
			F##_new(x1);													\
			F##_new(y1);													\
			F##_new(z1);													\
																			\
			F##_sqr(x1, u);													\
			F##_mul(x1, x1, u);												\
			F##_sqr(y1, t);													\
			F##_add(x1, x1, ctx->C##_b);									\
			F##_sub(x1, x1, y1);											\
			F##_dbl(y1, y1);												\
			F##_add(y1, y1, x1);											\
			F##_copy(z1, u);												\
			for (int i = 0; i < (int)(sizeof(F##_t) / sizeof(fp_t)); i++) {	\
				fp_mul(((fp_t *)z1)[i], ((fp_t *)z1)[i], ctx->ep_map_c[4]);	\
			}																\
			F##_mul(x1, x1, z1);											\
			F##_mul(z1, z1, t);												\
			F##_dbl(z1, z1);												\
																			\
			F##_dbl(y, y1);													\
			F##_sqr(y, y);													\
			F##_mul(v, y1, u);												\
			F##_sub(v, x1, v);												\
			F##_mul(v, v, z1);												\
			F##_mul(w, y1, z1);												\
			F##_dbl(w, w);													\
																			\
			if (F##_is_zero(w)) {											\
				C##_set_infty(p);											\
			} else {														\
				F##_inv(w, w);												\
				F##_mul(x1, v, w);											\
				F##_add(y1, u, x1);											\
				F##_neg(y1, y1);											\
				F##_mul(z1, y, w);											\
				F##_sqr(z1, z1);											\
				F##_add(z1, z1, u);											\
																			\
				C##_rhs(t, x1);												\
				C##_rhs(u, y1);												\
				C##_rhs(v, z1);												\
																			\
				c2 = F##_is_sqr(u);											\
				c3 = F##_is_sqr(v);											\
																			\
				F##_copy_sec(t, u, c2);										\
				F##_copy_sec(x1, y1, c2);									\
				F##_copy_sec(t, v, c3);										\
				F##_copy_sec(x1, z1, c3);									\
																			\
				if (!F##_srt(t, t)) {										\
					RLC_THROW(ERR_NO_VALID);								\
				}															\
																			\
				TMPL_EP_MAP_SGN0(F, t, k, sign);							\
				F##_neg(u, t);												\
				F##_copy_sec(t, u, sign);									\
																			\
				F##_copy(p->x, x1);											\
				F##_copy(p->y, t);											\
				F##_set_dig(p->z, 1);										\
				p->coord = BASIC;											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(k);														\
			F##_free(v);													\
			F##_free(w);													\
			F##_free(y);													\
			F##_free(x1);													\
			F##_free(y1);													\
			F##_free(z1);													\
		}																	\
	}

/**
 * Defines a template for mapping two extension field elements to an elliptic
 * curve with b = 0, combining three candidate abscissas so that one of them
 * yields a square.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MAP_B0(C, F)												\
	static void C##_map_b0(C##_t p, F##_t u, F##_t t, uint8_t sign) {		\
		const int D = (int)(sizeof(F##_t) / sizeof(fp_t));					\
		F##_t a, b, c, d, v, w, y, x1, y1, z1, den[3];						\
		dig_t c2, c3;														\
		bn_t k;																\
																			\
		bn_null(k);															\
		F##_null(a);														\
		F##_null(b);														\
		F##_null(c);														\
		F##_null(d);														\
		F##_null(v);														\
		F##_null(w);														\
		F##_null(y);														\
		F##_null(x1);														\
		F##_null(y1);														\
		F##_null(z1);														\
		F##_null(den[0]);													\
		F##_null(den[1]);													\
		F##_null(den[2]);													\
																			\
		RLC_TRY {															\
			bn_new(k);														\
			F##_new(a);														\
			F##_new(b);														\
			F##_new(c);														\
			F##_new(d);														\
			F##_new(v);														\
			F##_new(w);														\
			F##_new(y);														\
			F##_new(x1);													\
			F##_new(y1);													\
			F##_new(z1);													\
			F##_new(den[0]);												\
			F##_new(den[1]);												\
			F##_new(den[2]);												\
																			\
			F##_sqr(a, u);													\
			F##_sqr(b, a);													\
			F##_mul(c, b, a);												\
			F##_dbl(p->y, C##_curve_get_a());								\
			F##_dbl(p->y, p->y);											\
			F##_sqr(p->z, p->y);											\
			F##_mul(p->z, p->z, p->y);										\
			F##_add(c, c, p->z);											\
			F##_sqr(d, t);													\
																			\
			F##_mul(v, a, d);												\
			F##_mul(v, v, u);												\
			F##_mul_dig(v, v, 24);											\
			for (int i = 0; i < D; i++) {									\
				fp_mul(((fp_t *)v)[i], ((fp_t *)v)[i],						\
						core_get()->ep_map_c[4]);							\
			}																\
																			\
			F##_zero(p->x);													\
			fp_sub_dig(((fp_t *)p->x)[0], core_get()->ep_map_c[4], 1);		\
			fp_hlv(((fp_t *)p->x)[0], ((fp_t *)p->x)[0]);					\
																			\
			F##_sqr(w, b);													\
			F##_mul(y, v, a);												\
			F##_mul(t, p->y, c);											\
			F##_add(y, y, t);												\
			for (int i = 0; i < D; i++) {									\
				fp_mul(((fp_t *)y)[i], ((fp_t *)y)[i], ((fp_t *)p->x)[0]);	\
			}																\
																			\
			F##_add(den[0], c, v);											\
			F##_mul(den[0], den[0], u);										\
			for (int i = 0; i < D; i++) {									\
				fp_mul(((fp_t *)den[0])[i], ((fp_t *)den[0])[i],			\
						core_get()->ep_map_c[4]);							\
			}																\
			F##_mul(den[0], den[0], p->x);									\
			F##_dbl(den[0], den[0]);										\
			F##_neg(den[0], den[0]);										\
			F##_mul(den[1], den[0], p->x);									\
			F##_sub(den[2], a, p->y);										\
			F##_sqr(den[2], den[2]);										\
			F##_mul_dig(den[2], den[2], 216);								\
			F##_dbl(den[2], den[2]);										\
			F##_neg(den[2], den[2]);										\
			F##_mul(den[2], den[2], b);										\
			F##_mul(den[2], den[2], d);										\
																			\
			if (F##_is_zero(den[0]) || F##_is_zero(den[1]) ||				\
					F##_is_zero(den[2])) {									\
				C##_set_infty(p);											\
			} else {														\
				F##_inv_sim(den, den, 3);									\
				F##_mul(t, a, p->z);										\
				F##_mul(y1, p->y, v);										\
				F##_add(y1, y1, t);											\
				F##_add(y1, y1, w);											\
				for (int i = 0; i < D; i++) {								\
					fp_mul(((fp_t *)z1)[i], ((fp_t *)y)[i],					\
							((fp_t *)p->x)[0]);								\
				}															\
				F##_add(x1, y1, z1);										\
				F##_add(y1, y1, y);											\
				F##_mul(z1, a, p->y);										\
				F##_add(z1, z1, b);											\
				F##_mul(z1, z1, p->y);										\
				F##_dbl(p->x, z1);											\
				F##_add(z1, z1, p->x);										\
				F##_add(z1, z1, v);											\
				F##_sub(z1, c, z1);											\
				F##_mul(z1, z1, v);											\
				F##_sqr(p->z, p->z);										\
				F##_sub(z1, p->z, z1);										\
				F##_add(w, w, t);											\
				F##_add(w, w, t);											\
				F##_mul(w, w, b);											\
				F##_add(z1, z1, w);											\
																			\
				F##_mul(x1, x1, den[0]);									\
				F##_mul(y1, y1, den[1]);									\
				F##_mul(z1, z1, den[2]);									\
																			\
				C##_rhs(t, x1);												\
				C##_rhs(u, y1);												\
				C##_rhs(v, z1);												\
																			\
				c2 = F##_is_sqr(u);											\
				c3 = F##_is_sqr(v);											\
																			\
				F##_copy_sec(t, u, c2);										\
				F##_copy_sec(x1, y1, c2);									\
				F##_copy_sec(t, v, c3);										\
				F##_copy_sec(x1, z1, c3);									\
																			\
				if (!F##_srt(t, t)) {										\
					RLC_THROW(ERR_NO_VALID);								\
				}															\
																			\
				TMPL_EP_MAP_SGN0(F, t, k, sign);							\
				F##_neg(u, t);												\
				F##_copy_sec(t, u, sign);									\
																			\
				F##_copy(p->x, x1);											\
				F##_copy(p->y, t);											\
				F##_set_dig(p->z, 1);										\
				p->coord = BASIC;											\
			}																\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			bn_free(k);														\
			F##_free(a);													\
			F##_free(b);													\
			F##_free(c);													\
			F##_free(d);													\
			F##_free(v);													\
			F##_free(w);													\
			F##_free(y);													\
			F##_free(x1);													\
			F##_free(y1);													\
			F##_free(z1);													\
			F##_free(den[0]);												\
			F##_free(den[1]);												\
			F##_free(den[2]);												\
		}																	\
	}

/**
 * Defines a template for hashing to an elliptic curve with a = 0 over an
 * extension field, clearing the cofactor of the resulting point.
 *
 * @param[in] C			- the curve prefix.
 * @param[in] F			- the field prefix.
 */
#define TMPL_EP_MAP(C, F)													\
	TMPL_EP_MAP_INPUT(C, F)													\
	TMPL_EP_MAP_A0(C, F)													\
	void C##_map(C##_t p, const uint8_t *msg, size_t len) {					\
		F##_t u, t;															\
		uint8_t sign;														\
																			\
		F##_null(u);														\
		F##_null(t);														\
																			\
		RLC_TRY {															\
			F##_new(u);														\
			F##_new(t);														\
			sign = C##_map_input(u, t, msg, len);							\
			C##_map_a0(p, u, t, sign);										\
			C##_mul_cof(p, p);												\
		}																	\
		RLC_CATCH_ANY {														\
			RLC_THROW(ERR_CAUGHT);											\
		}																	\
		RLC_FINALLY {														\
			F##_free(u);													\
			F##_free(t);													\
		}																	\
	}
