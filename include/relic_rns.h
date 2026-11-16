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
 * @defgroup rns Residue Number System
 */

/**
 * @file
 *
 * Interface of the module for modular arithmetic in a Residue Number System.
 *
 * A context holds two bases B and B' of n moduli each, all primes of the form
 * 2^RLC_RNS_BITS - c coprime to a modulus N, and the tables for Montgomery
 * multiplication modulo N with M = prod(B) as the Montgomery constant. Values
 * are stored as their residues in both bases, each residue in Montgomery form
 * x_i * R mod m_i for R = 2^RLC_RNS_DIG, and divided by M in B'.
 *
 * @ingroup rns
 */

#ifndef RLC_RNS_H
#define RLC_RNS_H

#include "relic_conf.h"
#include "relic_util.h"
#include "relic_types.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Sizes in bits of the moduli, RLC_RNS_BITS, and of the digits of residues,
 * RLC_RNS_DIG, so that the radix of the Montgomery form of residues is
 * R = 2^RLC_RNS_DIG. The AVX-512 IFMA backend has 52-bit multipliers and 50-bit
 * moduli, so that sums of a few residues or products still fit them;
 * otherwise, the digits are whole and the moduli one bit shorter.
 */
#if RLC_ARITH == RLC_AVX512
#define RLC_RNS_BITS	50
#define RLC_RNS_DIG		52
#else
#define RLC_RNS_BITS	(RLC_DIG - 1)
#define RLC_RNS_DIG		RLC_DIG
#endif

/**
 * Largest number of moduli in a base, for moduli up to the precision of
 * multiple precision integers and sums of products of up to 2^32 times the
 * square of the modulus.
 */
#define RLC_RNS_MAX		RLC_RNS_SPAN(RLC_RNS_SIZE(BN_PRECI, 32))

/**
 * Number of residues in a vector of the backend, so that each base is padded
 * to whole vectors: eight with the AVX-512 IFMA backend, one otherwise.
 */
#if RLC_ARITH == RLC_AVX512
#define RLC_RNS_LANES	8
#else
#define RLC_RNS_LANES	1
#endif

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Returns the number of moduli in a base for a modulus of B bits, so that the
 * base exceeds 2^(R + 2) times the modulus: sums of products below 2^R times
 * the square of the modulus can then be reduced.
 *
 * @param[in] B				- the size of the modulus in bits.
 * @param[in] R				- the room for sums of products, in bits.
 */
#define RLC_RNS_SIZE(B, R)													\
	((size_t)(((B) + (R) + 3 + RLC_RNS_BITS - 1) / RLC_RNS_BITS))

/**
 * Returns the space taken by a base of N moduli, padded to whole vectors.
 *
 * @param[in] N				- the number of moduli.
 */
#define RLC_RNS_SPAN(N)														\
	(((N) + RLC_RNS_LANES - 1) / RLC_RNS_LANES * RLC_RNS_LANES)

/**
 * Returns the number of digits of RLC_RNS_DIG bits in an integer of D digits.
 *
 * @param[in] D				- the number of digits.
 */
#define RLC_RNS_WORDS(D)	RLC_CEIL((D) * RLC_DIG, RLC_RNS_DIG)

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents a context of the Residue Number System for a modulus N. The
 * tables are stored outside the context, in a block it owns or in storage of
 * the caller, and the context points to them.
 */
typedef struct {
	/** Number of moduli in each base. */
	size_t n;
	/** Space taken by each base, padded to whole vectors. */
	size_t o;
	/** Number of digits of the modulus N. */
	size_t d;
	/** Number of digits of RLC_RNS_DIG bits in an integer of d digits. */
	size_t w;
	/** Digits of the modulus N (d digits). */
	dig_t *p;
	/** M modulo N in storage form, which represents one (2o values). */
	dig_t *one;
	/** M^2 modulo N in storage form, to convert to Montgomery form (2o). */
	dig_t *cv;
	/** Moduli of B and then of B', padded with zeros (2o values). */
	dig_t *m;
	/** Values -m^{-1} mod R (2o values). */
	dig_t *u;
	/** Values m^{-1} mod R (2o values). */
	dig_t *iv;
	/** Values R^2 mod m (2o values). */
	dig_t *r2;
	/** Factors to store integers: R^2 in B and R^2 / M in B' (2o values). */
	dig_t *e;
	/** Values M^{-1} mod m'_j, in Montgomery form (n values). */
	dig_t *mi;
	/** Values (M/m_i)^{-1} mod m_i in B, and M (M'/m'_j)^{-1} in B' (2o). */
	dig_t *ib;
	/** Values -N^{-1} (M/m_i)^{-1} mod m_i in B (o values). */
	dig_t *nq;
	/** Values nq times m^{-1} mod R, for the vectorized reduction (o). */
	dig_t *nqv;
	/** Values ib times m^{-1} mod R in B', for the vectorized reduction (o). */
	dig_t *ibv;
	/** Tables of the extension from B to B' by row i (n rows of o values). */
	dig_t *t1;
	/** Tables of the extension from B' to B by row j (n rows of o values). */
	dig_t *t2;
	/** Values -M * N / M^2 * R^3 mod m'_j (o values). */
	dig_t *u1;
	/** Values -M' * R^3 mod m_i (o values). */
	dig_t *u2;
	/** The multiples kN for -2 <= k <= 2, in both bases (5 rows of 2o). */
	dig_t *kp;
	/** Low digits of M/m_i (n rows of d + 1 digits). */
	dig_t *mp;
	/** Low digits of -M (d + 1 digits). */
	dig_t *mm;
	/** Low digits of 3N (d + 1 digits). */
	dig_t *p3;
	/** Residues of 2^(RLC_RNS_DIG * k) in storage form (w rows of 2o). */
	dig_t *pw;
	/** Block of memory owned by the context, or NULL. */
	dig_t *mem;
} rns_st;

/**
 * Pointer to a context of the Residue Number System.
 */
typedef rns_st rns_t[1];

/* The types come first, as the CRT moduli sets of the BN module hold them. */
#include "relic_bn.h"

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes the cache of contexts of the library context.
 */
void rns_core_init(void);

/**
 * Frees the cache of contexts of the library context.
 */
void rns_core_clean(void);

/**
 * Supplies contexts to be searched by rns_lookup() before its cache, until
 * replaced. The contexts must stay valid meanwhile, and are not modified.
 *
 * @param[in] c				- the contexts, or NULL for none.
 * @param[in] n				- the number of contexts.
 */
void rns_hint(const rns_st *c, size_t n);

/**
 * Enables or disables the precomputation of missing contexts by rns_lookup(),
 * which is enabled by default, for code that knows its moduli will not be
 * used enough to pay for it.
 *
 * @param[in] flag			- 1 to enable, 0 to disable.
 * @return the previous setting.
 */
int rns_build(int flag);

/**
 * Returns a context for a modulus among those supplied by rns_hint() or else
 * from the cache of the library context. A missing context is precomputed in
 * place of the least recently used one only when the same modulus was also the
 * last one looked up without a context, as a modulus used once does not pay
 * for the precomputation, and when rns_build() allows it. A context from the
 * cache stays valid until two other moduli are looked up.
 *
 * @param[in] mod			- the modulus.
 * @param[in] room			- the room for sums of products, in bits.
 * @return the context, or NULL if there is none for the modulus.
 */
const rns_st *rns_lookup(const bn_t mod, int room);

/**
 * Returns the number of digits of the tables of a context.
 *
 * @param[in] n				- the number of moduli in each base.
 * @param[in] d				- the number of digits of the modulus.
 * @return the number of digits.
 */
size_t rns_size(size_t n, size_t d);

/**
 * Allocates the tables of a context in a block that the context owns.
 *
 * @param[out] c			- the context.
 * @param[in] n				- the number of moduli in each base.
 * @param[in] d				- the number of digits of the modulus.
 * @throw ERR_NO_VALID		- if the sizes exceed RLC_RNS_MAX or RLC_BN_DIGS.
 * @throw ERR_NO_MEMORY		- if there is no available memory.
 */
void rns_new(rns_t c, size_t n, size_t d);

/**
 * Frees the block of a context, if it owns one.
 *
 * @param[out] c			- the context.
 */
void rns_free(rns_t c);

/**
 * Precomputes the bases and the tables of a context for a modulus. The context
 * must have its tables in place, sized for the modulus.
 *
 * @param[in,out] c			- the context.
 * @param[in] mod			- the modulus.
 * @param[in] room			- the room for sums of products, in bits.
 * @throw ERR_NO_VALID		- if the bases do not fit the modulus and the room.
 */
void rns_pre(rns_t c, const bn_t mod, int room);

/**
 * Converts an integer to its residues in both bases, exactly: the integer is
 * not reduced modulo N nor scaled to the Montgomery form of products, so it
 * must be smaller than M/2 in absolute value. Meant for precomputation and for
 * testing the bounds of the arithmetic.
 *
 * @param[out] r			- the 2o residues.
 * @param[in] a				- the integer to convert.
 * @param[in] c				- the context.
 */
void rns_conv(dig_t *r, const bn_t a, const rns_t c);

/**
 * Converts the residues in the first base back to an integer by the Chinese
 * Remainder Theorem: the exact integer in (-M/2, M/2], not reduced modulo N.
 * Meant for precomputation and for testing the bounds of the arithmetic.
 *
 * @param[out] r			- the result.
 * @param[in] a				- the 2o residues.
 * @param[in] c				- the context.
 */
void rns_back(bn_t r, const dig_t *a, const rns_t c);

/**
 * Converts a value in the Residue Number System to the digits of its residue
 * modulo N in [0, N), in constant time.
 *
 * @param[out] r			- the d digits.
 * @param[in] a				- the value.
 * @param[in] c				- the context.
 */
void rns_get(dig_t *r, const dig_t *a, const rns_t c);

/**
 * Converts the digits of an integer to a value in the Residue Number System
 * with that residue modulo N, in constant time.
 *
 * @param[out] r			- the value.
 * @param[in] a				- the d digits.
 * @param[in] c				- the context.
 */
void rns_set(dig_t *r, const dig_t *a, const rns_t c);

/**
 * Converts a value in the Residue Number System to its residue modulo N in
 * [0, N), as an integer.
 *
 * @param[out] r			- the result.
 * @param[in] a				- the value.
 * @param[in] c				- the context.
 */
void rns_get_bn(bn_t r, const dig_t *a, const rns_t c);

/**
 * Converts an integer of any sign and size to a value in the Residue Number
 * System with the same residue modulo N. The integer is reduced by division,
 * which is not constant time.
 *
 * @param[out] r			- the value.
 * @param[in] a				- the integer.
 * @param[in] c				- the context.
 */
void rns_set_bn(dig_t *r, const bn_t a, const rns_t c);

/**
 * Tests if a value in the Residue Number System is zero modulo N, in constant
 * time.
 *
 * @param[in] a				- the value to test.
 * @param[in] c				- the context.
 * @return 1 if the value is zero modulo N, 0 otherwise.
 */
int rns_is_zero(const dig_t *a, const rns_t c);

#endif /* !RLC_RNS_H */
