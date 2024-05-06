/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * @defgroup fp Prime field arithmetic
 */

/**
 * @file
 *
 * Interface of the module for prime field arithmetic.
 *
 * @ingroup fp
 */

#ifndef RLC_FP_H
#define RLC_FP_H

#include "relic_dv.h"
#include "relic_bn.h"
#include "relic_conf.h"
#include "relic_types.h"

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/**
 * Precision in bits of a prime field element.
 */
#define RLC_FP_BITS 	((size_t)FP_PRIME)

/**
 * Size in digits of a block sufficient to store a prime field element.
 */
#define RLC_FP_DIGS 	((size_t)RLC_CEIL(RLC_FP_BITS, RLC_DIG))

/**
 * Size in bytes of a block sufficient to store a binary field element.
 */
#define RLC_FP_BYTES 	((size_t)RLC_CEIL(RLC_FP_BITS, 8))

/*
 * Finite field identifiers.
 */
enum {
    /** Mersenne prime with 127 bits. */
    MP_127 = 1,
	/** SECG 160-bit fast reduction prime. */
	SECG_160,
	/** SECG 160-bit denser reduction prime. */
	SECG_160D,
	/** NIST 192-bit fast reduction prime. */
	NIST_192,
	/** SECG 192-bit denser reduction prime. */
	SECG_192,
	/** Curve22103 221-bit prime modulus. */
	PRIME_22103,
	/** NIST 224-bit fast reduction polynomial. */
	NIST_224,
	/** SECG 224-bit denser reduction prime. */
	SECG_224,
	/** Curve4417 226-bit prime modulus. */
	PRIME_22605,
	/* Curve1174 251-bit prime modulus. */
	PRIME_25109,
	/** Prime with high 2-adicity for curve Tweedledum. */
	PRIME_H2ADC,
	/** 254-bit prime modulus for SQISign at NIST level 1. */
	SQI_254,
	/** Curve25519 255-bit prime modulus. */
	PRIME_25519,
	/** NIST 256-bit fast reduction polynomial. */
	NIST_256,
	/** Brainpool random 256-bit prime. */
	BSI_256,
	/** SECG 256-bit denser reduction prime. */
	SECG_256,
	/** SM2 256-bit prime modulus standardized in China. */
	SM2_256,
	/** Curve67254 382-bit prime modulus. */
	PRIME_382105,
	/** Curve383187 383-bit prime modulus. */
	PRIME_383187,
	/** NIST 384-bit fast reduction polynomial. */
	NIST_384,
	/** Curve448 prime. */
	PRIME_448,
	/** 511-bit prime for CTIDH. */
	CTIDH_511,
	/** Curve511187 511-bit prime modulus. */
	PRIME_511187,
	/** NIST 521-bit fast reduction polynomial. */
	NIST_521,
	/** 158-bit prime for BN curve. */
	BN_158,
	/** 254-bit prime provided in Nogami et al. for BN curves. */
	BN_254,
	/** 256-bit prime provided in Barreto et al. for BN curves. */
	BN_256,
	/** 256-bit prime provided for BN curve standardized in China. */
	SM9_256,
	/** 315-bit prime for BLS curve of embedding degree 24 (SNARKs). */
	B24_315,
	/** 317-bit prime for BLS curve of embedding degree 24 (SNARKs). */
	B24_317,
	/** 330-bit prime for KSS curve with embedding degree 16. */
	K16_330,
	/** 381-bit prime for BLS curve of embedding degree 12 (SNARKs). */
	B12_377,
	/** 381-bit prime for BLS curve of embedding degree 12 (Zcash). */
	B12_381,
	/** 382-bit prime provided by Barreto for BN curve. */
	BN_382,
	/** 383-bit prime for GT-strong BLS curve of embedding degree 12. */
	B12_383,
	/** 446-bit prime provided by Barreto for BN curve. */
	BN_446,
	/** 446-bit prime for BLS curve of embedding degree 12. */
	B12_446,
	/** 455-bit prime for BLS curve of embedding degree 12. */
	B12_455,
	/** 477-bit prime for BLS curve of embedding degree 24. */
	B24_509,
	/** 508-bit prime for KSS16 curve. */
	K18_508,
	/** Random 544-bit prime for Cocks-Pinch curve with embedding degree 8. */
	GMT8_544,
	/** 569-bit prime for SG curve with embedding degree 54. */
	SG54_569,
	/** 575-bit prime for BLS curve with embedding degree 48. */
	B48_575,
	/** 638-bit prime provided in Barreto et al. for BN curve. */
	BN_638,
	/** 638-bit prime for BLS curve with embedding degree 12. */
	B12_638,
	/** 638-bit prime for KSS curve with embedding degree 18. */
	K18_638,
    /** 638-bit prime for SG curve with embedding degree 18. */
    SG18_638,
	/** 765-bit prime for FM curve with embedding degree 16. */
	FM16_765,
	/** 766-bit prime for KSS curve with embedding degree 16. */
	K16_766,
	/** 766-bit prime for new family with embedding degree 16. */
	N16_766,
	/** 768-bit prime for FM curve with embedding degree 18. */
	FM18_768,
	/** 1024-bit prime for CTIDH. */
	CTIDH_1024,
	/** 1150-bit prime for BLS curve with embedding degree 12. */
	B12_1150,
	/** 1536-bit prime for supersingular curve with embedding degree k = 2. */
	SS_1536,
	/** 2048-bit prime for CTDIH. */
	CTIDH_2048,
	/** 3072-bit prime for supersingular curve with embedding degree k = 1. */
	K1_3072,
	/** 4096-bit prime for SQALE. */
	SQALE_4096,
};

/**
 * Constant used to indicate that there's some room left in the storage of
 * prime field elements. This can be used to avoid carries.
 */
#if ((FP_PRIME % WSIZE) != 0) && ((FP_PRIME % WSIZE) <= (WSIZE - 2))
#if ((2 * FP_PRIME % WSIZE) != 0) && ((2 * FP_PRIME % WSIZE) <= (WSIZE - 2))
#define RLC_FP_ROOM
#else
#undef RLC_FP_ROOM
#endif
#else
#undef RLC_FP_ROOM
#endif

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/**
 * Represents a prime field element.
 *
 * A field element is represented as a digit vector. These digits are organized
 * in little-endian format, that is, the least significant digits are
 * stored in the first positions of the vector.
 */
#if ALLOC == AUTO
typedef rlc_align dig_t fp_t[RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)];
#else
typedef dig_t *fp_t;
#endif

/**
 * Represents a prime field element with automatic memory allocation.
 */
typedef rlc_align dig_t fp_st[RLC_FP_DIGS + RLC_PAD(RLC_FP_BYTES)/(RLC_DIG / 8)];

/*============================================================================*/
/* Macro definitions                                                          */
/*============================================================================*/

/**
 * Initializes a binary field element with a null value.
 *
 * @param[out] A			- the binary field element to initialize.
 */
#if ALLOC == AUTO
#define fp_null(A)			/* empty */
#else
#define fp_null(A)			A = NULL;
#endif

/**
 * Calls a function to allocate and initialize a prime field element.
 *
 * @param[out] A			- the new prime field element.
 */
#if ALLOC == DYNAMIC
#define fp_new(A)			dv_new_dynam((dv_t *)&(A), RLC_FP_DIGS)
#elif ALLOC == AUTO
#define fp_new(A)			/* empty */
#endif

/**
 * Calls a function to clean and free a prime field element.
 *
 * @param[out] A			- the prime field element to clean and free.
 */
#if ALLOC == DYNAMIC
#define fp_free(A)			dv_free_dynam((dv_t *)&(A))
#elif ALLOC == AUTO
#define fp_free(A)			/* empty */
#endif

/**
 * Adds two prime field elements. Computes c = a + b.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the first prime field element.
 * @param[in] B				- the second prime field element.
 */
#if FP_ADD == BASIC
#define fp_add(C, A, B)		fp_add_basic(C, A, B)
#elif FP_ADD == INTEG
#define fp_add(C, A, B)		fp_add_integ(C, A, B)
#endif

/**
 * Subtracts a prime field element from another. Computes C = A - B.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the first prime field element.
 * @param[in] B				- the second prime field element.
 */
#if FP_ADD == BASIC
#define fp_sub(C, A, B)		fp_sub_basic(C, A, B)
#elif FP_ADD == INTEG
#define fp_sub(C, A, B)		fp_sub_integ(C, A, B)
#endif

/**
 * Negates a prime field element from another. Computes C = -A.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the prime field element to negate.
 */
#if FP_ADD == BASIC
#define fp_neg(C, A)		fp_neg_basic(C, A)
#elif FP_ADD == INTEG
#define fp_neg(C, A)		fp_neg_integ(C, A)
#endif

/**
 * Doubles a prime field element. Computes C = A + A.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the first prime field element.
 */
#if FP_ADD == BASIC
#define fp_dbl(C, A)		fp_dbl_basic(C, A)
#elif FP_ADD == INTEG
#define fp_dbl(C, A)		fp_dbl_integ(C, A)
#endif

/**
 * Halves a prime field element. Computes C = A/2.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the first prime field element.
 */
#if FP_ADD == BASIC
#define fp_hlv(C, A)		fp_hlv_basic(C, A)
#elif FP_ADD == INTEG
#define fp_hlv(C, A)		fp_hlv_integ(C, A)
#endif

/**
 * Multiples two prime field elements. Computes C = A * B.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the first prime field element.
 * @param[in] B				- the second prime field element.
 */
#if FP_KARAT > 0
#define fp_mul(C, A, B)		fp_mul_karat(C, A, B)
#elif FP_MUL == BASIC
#define fp_mul(C, A, B)		fp_mul_basic(C, A, B)
#elif FP_MUL == COMBA
#define fp_mul(C, A, B)		fp_mul_comba(C, A, B)
#elif FP_MUL == INTEG
#define fp_mul(C, A, B)		fp_mul_integ(C, A, B)
#endif

/**
 * Squares a prime field element. Computes C = A * A.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the prime field element to square.
 */
#if FP_KARAT > 0
#define fp_sqr(C, A)		fp_sqr_karat(C, A)
#elif FP_SQR == BASIC
#define fp_sqr(C, A)		fp_sqr_basic(C, A)
#elif FP_SQR == COMBA
#define fp_sqr(C, A)		fp_sqr_comba(C, A)
#elif FP_SQR == MULTP
#define fp_sqr(C, A)		fp_mul(C, A, A)
#elif FP_SQR == INTEG
#define fp_sqr(C, A)		fp_sqr_integ(C, A)
#endif

/**
 * Reduces a multiplication result modulo a prime field order. Computes
 * C = A mod p.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the multiplication result to reduce.
 */
#if FP_RDC == BASIC
#define fp_rdc(C, A)		fp_rdc_basic(C, A)
#elif FP_RDC == MONTY
#define fp_rdc(C, A)		fp_rdc_monty(C, A)
#elif FP_RDC == QUICK
#define fp_rdc(C, A)		fp_rdc_quick(C, A)
#endif

/**
 * Reduces a multiplication result modulo a prime field order using Montgomery
 * modular reduction.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the multiplication result to reduce.
 */
#if FP_MUL == BASIC
#define fp_rdc_monty(C, A)	fp_rdc_monty_basic(C, A)
#else
#define fp_rdc_monty(C, A)	fp_rdc_monty_comba(C, A)
#endif

/**
 * Inverts a prime field element. Computes C = A^{-1}.
 *
 * @param[out] C			- the result.
 * @param[in] A				- the prime field element to invert.
 */
#if FP_INV == BASIC
#define fp_inv(C, A)	fp_inv_basic(C, A)
#elif FP_INV == BINAR
#define fp_inv(C, A)	fp_inv_binar(C, A)
#elif FP_INV == MONTY
#define fp_inv(C, A)	fp_inv_monty(C, A)
#elif FP_INV == EXGCD
#define fp_inv(C, A)	fp_inv_exgcd(C, A)
#elif FP_INV == DIVST
#define fp_inv(C, A)	fp_inv_divst(C, A)
#elif FP_INV == JMPDS
#define fp_inv(C, A)	fp_inv_jmpds(C, A)
#elif FP_INV == LOWER
#define fp_inv(C, A)	fp_inv_lower(C, A)
#endif

/**
 * Computes the Legendre symbol of a prime field element. Computes C = (A|P).
 *
 * @param[out] C			- the result.
 * @param[in] A				- the prime field element to compute.
 */
#if FP_SMB == BASIC
#define fp_smb(A)		fp_smb_basic(A)
#elif FP_SMB == DIVST
#define fp_smb(A)		fp_smb_divst(A)
#elif FP_SMB == JMPDS
#define fp_smb(A)		fp_smb_jmpds(A)
#elif FP_SMB == LOWER
#define fp_smb(A)		fp_smb_lower(A)
#endif

/**
 * Exponentiates a prime field element. Computes C = A^B (mod p).
 *
 * @param[out] C			- the result.
 * @param[in] A				- the basis.
 * @param[in] B				- the exponent.
 */
#if FP_EXP == BASIC
#define fp_exp(C, A, B)		fp_exp_basic(C, A, B)
#elif FP_EXP == SLIDE
#define fp_exp(C, A, B)		fp_exp_slide(C, A, B)
#elif FP_EXP == MONTY
#define fp_exp(C, A, B)		fp_exp_monty(C, A, B)
#endif

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initializes the prime field arithmetic layer.
 */
void fp_prime_init(void);

/**
 * Finalizes the prime field arithmetic layer.
 */
void fp_prime_clean(void);

/**
 * Returns the order of the prime field.
 *
 * @return the order of the prime field.
 */
const dig_t *fp_prime_get(void);

/**
 * Returns the additional value used for modular reduction.
 *
 * @return the additional value used for modular reduction.
 */
const dig_t *fp_prime_get_rdc(void);

/**
 * Returns the additional value used for conversion from multiple precision
 * integer to prime field element.
 *
 * @return the additional value used for importing integers.
 */
const dig_t *fp_prime_get_conv(void);

/**
 * Returns a 2^f-root of unity modulo the prime field modulus, for the maximum f
 * such that 2^f divides (p-1).
 *
 * @return the root of unity.
 */
const dig_t *fp_prime_get_srt(void);

/**
 * Returns a 3^f-root of unity modulo the prime field modulus, for the maximum f
 * such that 3^f divides (p-1).
 *
 * @return the root of unity.
 */
const dig_t *fp_prime_get_crt(void);

/**
 * Returns the result of prime order mod 8.
 *
 * @return the result of prime order mod 8.
 */
dig_t fp_prime_get_mod8(void);

/**
 * Returns the result of prime order mod 18.
 *
 * @return the result of prime order mod 18.
 */
dig_t fp_prime_get_mod18(void);

/**
 * Returns the prime stored in special form. The most significant bit is
 * RLC_FP_BITS.
 *
 * @param[out] len		- the number of returned bits, can be NULL.
 *
 * @return the prime represented by it non-zero bits.
 */
const int *fp_prime_get_sps(int *len);

/**
 * Returns a non-quadratic residue in the prime field.
 *
 * @return the non-quadratic residue.
 */
int fp_prime_get_qnr(void);

/**
 * Returns a non-cubic residue in the prime field.
 *
 * @return the non-cubic residue.
 */
int fp_prime_get_cnr(void);

/**
 * Returns the 2-adicity of the prime modulus.
 *
 * @return the 2-adicity of the modulus.
 */
int fp_prime_get_2ad(void);

/**
 * Returns the prime field parameter identifier.
 *
 * @return the parameter identifier.
 */
int fp_param_get(void);

/**
 * Assigns the prime field modulus to a non-sparse prime.
 *
 * @param[in] p			- the new prime field modulus.
 */
void fp_prime_set_dense(const bn_t p);

/**
 * Assigns the prime field modulus to a special form sparse prime.
 *
 * @param[in] spars		- the list of powers of 2 describing the prime.
 * @param[in] len		- the number of powers.
 */
void fp_prime_set_pmers(const int *spars, size_t len);

/**
 * Assigns the prime field modulus to a parametrization from a family of
 * pairing-friendly curves.
 */
void fp_prime_set_pairf(const bn_t x, int pairf);

/**
 * Computes the constants needed for evaluating Frobenius maps in higher
 * extension fields.
 */
void fp_prime_calc(void);

/**
 * Imports a multiple precision integer as a prime field element, doing the
 * necessary conversion.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiple precision integer to import.
 */
void fp_prime_conv(fp_t c, const bn_t a);

/**
 * Imports a single digit as a prime field element, doing the necessary
 * conversion.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit to import.
 */
void fp_prime_conv_dig(fp_t c, dig_t a);

/**
 * Exports a prime field element as a multiple precision integer, doing the
 * necessary conversion.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to export.
 */
void fp_prime_back(bn_t c, const fp_t a);

/**
 * Assigns a prime modulus based on its identifier.
 */
void fp_param_set(int param);

/**
 * Assigns any pre-defined parameter as the prime modulus.
 *
 * @return RLC_OK if no errors occurred; RLC_ERR otherwise.
 */
int fp_param_set_any(void);

/**
 * Assigns the order of the prime field to any non-sparse prime.
 *
 * @return RLC_OK if no errors occurred; RLC_ERR otherwise.
 */
int fp_param_set_any_dense(void);

/**
 * Assigns the order of the prime field to any sparse prime.
 *
 * @return RLC_OK if no errors occurred; RLC_ERR otherwise.
 */
int fp_param_set_any_pmers(void);

/**
 * Assigns the order of the prime field to any towering-friendly prime.
 *
 * @return RLC_OK if no errors occurred; RLC_ERR otherwise.
 */
int fp_param_set_any_tower(void);

/**
 * Assigns the order of the prime field to a prime with high 2-adicity..
 *
 * @return RLC_OK if no errors occurred; RLC_ERR otherwise.
 */
int fp_param_set_any_h2adc(void);

/**
 * Prints the currently configured prime modulus.
 */
void fp_param_print(void);

/**
 * Returns the variable used to parametrize the given prime modulus.
 *
 * @param[out] x			- the integer parameter.
 */
void fp_prime_get_par(bn_t x);

/**
 * Returns the absolute value of the variable used to parameterize the given
 * prime modulus in sparse form.
 *
 * @param[out] len			- the length of the representation.
 */
const int *fp_prime_get_par_sps(int *len);

/**
 * Returns the absolute value of the variable used to parameterize the currently
 * configured prime modulus in sparse form. The first argument must be an array
 * of size (RLC_TERMS + 1).
 *
 * @param[out] s			- the parameter in sparse form.
 * @param[out] len			- the length of the parameter in sparse form.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is insufficient.
 * @throw ERR_NO_VALID		- if the current configuration is invalid.
 * @return the integer parameter in sparse form.
 */
void fp_param_get_sps(int *s, int *len);

/**
 * Copies the second argument to the first argument.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to copy.
 */
void fp_copy(fp_t c, const fp_t a);

/**
 * Conditionally copies a field element to another field element.
 *
 * @param[out] c			- the destination.
 * @paraim[in] a			- the source.
 * @param[in] bit			- the condition bit to evaluate.
 */
void fp_copy_sec(fp_t c, const fp_t a, dig_t bit);

/**
 * Assigns zero to a prime field element.
 *
 * @param[out] a			- the prime field element to asign.
 */
void fp_zero(fp_t a);

/**
 * Tests if a prime field element is zero or not.
 *
 * @param[in] a				- the prime field element to test.
 * @return 1 if the argument is zero, 0 otherwise.
 */
int fp_is_zero(const fp_t a);

/**
 * Tests if a prime field element is even or odd.
 *
 * @param[in] a				- the prime field element to test.
 * @return 1 if the argument is even, 0 otherwise.
 */
int fp_is_even(const fp_t a);

/**
 * Reads the bit stored in the given position on a prime field element.
 *
 * @param[in] a				- the prime field element.
 * @param[in] bit			- the bit position.
 * @return the bit value.
 */
int fp_get_bit(const fp_t a, uint_t bit);

/**
 * Stores a bit in a given position on a prime field element.
 *
 * @param[out] a			- the prime field element.
 * @param[in] bit			- the bit position.
 * @param[in] value			- the bit value.
 */
void fp_set_bit(fp_t a, uint_t bit, int value);

/**
 * Assigns a small positive constant to a prime field element.
 *
 * The constant must fit on a multiple precision digit, or dig_t type using
 * only the number of bits specified on RLC_DIG.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the constant to assign.
 */
void fp_set_dig(fp_t c, dig_t a);

/**
 * Returns the number of bits of a prime field element.
 *
 * @param[in] a				- the prime field element.
 * @return the number of bits.
 */
size_t fp_bits(const fp_t a);

/**
 * Assigns a random value to a prime field element.
 *
 * @param[out] a			- the prime field element to assign.
 */
void fp_rand(fp_t a);

/**
 * Normalizes a prime field element to a representative in [0, p - 1].
 *
 * @param[out] c 			- the normalized field element.
 * @param[in] a 			- the field element to normalize-
 */
void fp_norm(fp_t c, const fp_t a);

/**
 * Prints a prime field element to standard output.
 *
 * @param[in] a				- the prime field element to print.
 */
void fp_print(const fp_t a);

/**
 * Returns the number of digits in radix necessary to store a multiple precision
 * integer. The radix must be a power of 2 included in the interval [2, 64].
 *
 * @param[in] a				- the prime field element.
 * @param[in] radix			- the radix.
 * @throw ERR_NO_VALID		- if the radix is invalid.
 * @return the number of digits in the given radix.
 */
size_t fp_size_str(const fp_t a, uint_t radix);

/**
 * Reads a prime field element from a string in a given radix. The radix must
 * be a power of 2 included in the interval [2, 64].
 *
 * @param[out] a			- the result.
 * @param[in] str			- the string.
 * @param[in] len			- the size of the string.
 * @param[in] radix			- the radix.
 * @throw ERR_NO_VALID		- if the radix is invalid.
 */
void fp_read_str(fp_t a, const char *str, size_t len, uint_t radix);

/**
 * Writes a prime field element to a string in a given radix. The radix must
 * be a power of 2 included in the interval [2, 64].
 *
 * @param[out] str			- the string.
 * @param[in] len			- the buffer capacity.
 * @param[in] a				- the prime field element to write.
 * @param[in] radix			- the radix.
 * @throw ERR_BUFFER		- if the buffer capacity is insufficient.
 * @throw ERR_NO_VALID		- if the radix is invalid.
 */
void fp_write_str(char *str, size_t len, const fp_t a, uint_t radix);

/**
 * Reads a prime field element from a byte vector in big-endian format.
 *
 * @param[out] a			- the result.
 * @param[in] bin			- the byte vector.
 * @param[in] len			- the buffer capacity.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is not RLC_FP_BYTES.
 */
void fp_read_bin(fp_t a, const uint8_t *bin, size_t len);

/**
 * Writes a prime field element to a byte vector in big-endian format.
 *
 * @param[out] bin			- the byte vector.
 * @param[in] len			- the buffer capacity.
 * @param[in] a				- the prime field element to write.
 * @throw ERR_NO_BUFFER		- if the buffer capacity is not RLC_FP_BYTES.
 */
void fp_write_bin(uint8_t *bin, size_t len, const fp_t a);

/**
 * Returns the result of a comparison between two prime field elements.
 *
 * @param[in] a				- the first prime field element.
 * @param[in] b				- the second prime field element.
 * @return RLC_EQ if a == b, and RLC_NE otherwise.
 */
int fp_cmp(const fp_t a, const fp_t b);

/**
 * Returns the result of a signed comparison between a prime field element
 * and a digit.
 *
 * @param[in] a				- the prime field element.
 * @param[in] b				- the digit.
 * @return RLC_EQ if a == b, and RLC_NE otherwise.
 */
int fp_cmp_dig(const fp_t a, dig_t b);

/**
 * Adds two prime field elements using basic addition. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to add.
 * @param[in] b				- the second prime field element to add.
 */
void fp_add_basic(fp_t c, const fp_t a, const fp_t b);

/**
 * Adds two prime field elements with integrated modular reduction. Computes
 * c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to add.
 * @param[in] b				- the second prime field element to add.
 */
void fp_add_integ(fp_t c, const fp_t a, const fp_t b);

/**
 * Adds a prime field element and a digit. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to add.
 * @param[in] b				- the digit to add.
 */
void fp_add_dig(fp_t c, const fp_t a, dig_t b);

/**
 * Subtracts a prime field element from another using basic subtraction.
 * Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element.
 * @param[in] b				- the prime field element to subtract.
 */
void fp_sub_basic(fp_t c, const fp_t a, const fp_t b);

/**
 * Subtracts a prime field element from another with integrated modular
 * reduction. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element.
 * @param[in] b				- the prime field element to subtract.
 */
void fp_sub_integ(fp_t c, const fp_t a, const fp_t b);

/**
 * Subtracts a digit from a prime field element. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element.
 * @param[in] b				- the digit to subtract.
 */
void fp_sub_dig(fp_t c, const fp_t a, dig_t b);

/**
 * Negates a prime field element using basic negation.
 *
 * @param[out] c			- the result.
 * @param[out] a			- the prime field element to negate.
 */
void fp_neg_basic(fp_t c, const fp_t a);

/**
 * Negates a prime field element using integrated negation.
 *
 * @param[out] c			- the result.
 * @param[out] a			- the prime field element to negate.
 */
void fp_neg_integ(fp_t c, const fp_t a);

/**
 * Doubles a prime field element using basic addition.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to add.
 */
void fp_dbl_basic(fp_t c, const fp_t a);

/**
 * Doubles a prime field element with integrated modular reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to add.
 */
void fp_dbl_integ(fp_t c, const fp_t a);

/**
 * Halves a prime field element.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to halve.
 */
void fp_hlv_basic(fp_t c, const fp_t a);

/**
 * Halves a prime field element with integrated modular reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to halve.
 */
void fp_hlv_integ(fp_t c, const fp_t a);

/**
 * Multiples two prime field elements using Schoolbook multiplication.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to multiply.
 * @param[in] b				- the second prime field element to multiply.
 */
void fp_mul_basic(fp_t c, const fp_t a, const fp_t b);

/**
 * Multiples two prime field elements using Comba multiplication.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to multiply.
 * @param[in] b				- the second prime field element to multiply.
 */
void fp_mul_comba(fp_t c, const fp_t a, const fp_t b);

/**
 * Multiples two prime field elements using multiplication integrated with
 * modular reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to multiply.
 * @param[in] b				- the second prime field element to multiply.
 */
void fp_mul_integ(fp_t c, const fp_t a, const fp_t b);

/**
 * Multiples two prime field elements using Karatsuba multiplication.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first prime field element to multiply.
 * @param[in] b				- the second prime field element to multiply.
 */
void fp_mul_karat(fp_t c, const fp_t a, const fp_t b);

/**
 * Multiplies a prime field element by a digit. Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element.
 * @param[in] b				- the digit to multiply.
 */
void fp_mul_dig(fp_t c, const fp_t a, dig_t b);

/**
 * Squares a prime field element using Schoolbook squaring.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to square.
 */
void fp_sqr_basic(fp_t c, const fp_t a);

/**
 * Squares a prime field element using Comba squaring.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to square.
 */
void fp_sqr_comba(fp_t c, const fp_t a);

/**
 * Squares two prime field elements using squaring integrated with
 * modular reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the binary field element to square.
 */
void fp_sqr_integ(fp_t c, const fp_t a);

/**
 * Squares a prime field element using Karatsuba squaring.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to square.
 */
void fp_sqr_karat(fp_t c, const fp_t a);

/**
 * Shifts a prime field element number to the left. Computes
 * c = a * 2^bits.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to shift.
 * @param[in] bits			- the number of bits to shift.
 */
void fp_lsh(fp_t c, const fp_t a, uint_t bits);

/**
 * Shifts a prime field element to the right. Computes c = floor(a / 2^bits).
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to shift.
 * @param[in] bits			- the number of bits to shift.
 */
void fp_rsh(fp_t c, const fp_t a, uint_t bits);

/**
 * Reduces a multiplication result modulo the prime field modulo using
 * division-based reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiplication result to reduce.
 */
void fp_rdc_basic(fp_t c, dv_t a);

/**
 * Reduces a multiplication result modulo the prime field order using Shoolbook
 * Montgomery reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiplication result to reduce.
 */
void fp_rdc_monty_basic(fp_t c, dv_t a);

/**
 * Reduces a multiplication result modulo the prime field order using Comba
 * Montgomery reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiplication result to reduce.
 */
void fp_rdc_monty_comba(fp_t c, dv_t a);

/**
 * Reduces a multiplication result modulo the prime field modulo using
 * fast reduction.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the multiplication result to reduce.
 */
void fp_rdc_quick(fp_t c, dv_t a);

/**
 * Inverts a prime field element using Fermat's Little Theorem.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to invert.
 * @throw ERR_NO_VALID		- if the field element is not invertible.
 */
void fp_inv_basic(fp_t c, const fp_t a);

/**
 * Inverts a prime field element using the binary method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to invert.
 * @throw ERR_NO_VALID		- if the field element is not invertible.
 */
void fp_inv_binar(fp_t c, const fp_t a);

/**
 * Inverts a prime field element using Montgomery inversion.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to invert.
 * @throw ERR_NO_VALID		- if the field element is not invertible.
 */
void fp_inv_monty(fp_t c, const fp_t a);

/**
 * Inverts a prime field element using the Euclidean Extended Algorithm.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to invert.
 * @throw ERR_NO_VALID		- if the field element is not invertible.
 */
void fp_inv_exgcd(fp_t c, const fp_t a);

/**
 * Inverts a prime field element using the constant-time division step approach
 * by Bernstein and Bo-Yin Yang.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to invert.
 * @throw ERR_NO_VALID		- if the field element is not invertible.
 */
void fp_inv_divst(fp_t c, const fp_t a);

/**
 * Inverts a prime field element using the constant-time jump division step
 * by Bernstein and Bo-Yin Yang.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to invert.
 * @throw ERR_NO_VALID		- if the field element is not invertible.
 */
void fp_inv_jmpds(fp_t c, const fp_t a);

/**
 * Inverts a prime field element using a direct call to the lower layer.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element to invert.
 * @throw ERR_NO_VALID		- if the field element is not invertible.
 */
void fp_inv_lower(fp_t c, const fp_t a);

/**
 * Inverts multiple prime field elements simultaneously.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field elements to invert.
 * @param[in] n				- the number of elements.
 */
void fp_inv_sim(fp_t *c, const fp_t *a, int n);

/**
 * Computes Legendre symbol of a prime field element using exponentiation.
 *
 * @param[in] a				- the prime field element to compute.
 * @return the result.
 */
int fp_smb_basic(const fp_t a);

/**
 * Computes Legendre symbol of a prime field element using the constant-time
 * division step approach by Bernstein and Bo-Yin Yang.
 *
 * @param[in] a				- the prime field element to compute.
 * @return the result.
 */
int fp_smb_divst(const fp_t a);

/**
 * Computes Legendre symbol of a prime field element using the constant-time
 * jump division step approach by Bernstein and Bo-Yin Yang.
 *
 * @param[in] a				- the prime field element to compute.
 * @return the result.
 */
int fp_smb_jmpds(const fp_t a);

/**
 * Computes Legendre symbol a prime field element using a direct call to the
 * lower layer.
 *
 * @param[in] a				- the prime field element to invert.
 * @return the result.
 */
int fp_smb_lower(const fp_t a);

/**
 * Exponentiates a prime field element using the binary
 * method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 */
void fp_exp_basic(fp_t c, const fp_t a, const bn_t b);

/**
 * Exponentiates a prime field element using the sliding window method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 */
void fp_exp_slide(fp_t c, const fp_t a, const bn_t b);

/**
 * Exponentiates a prime field element using the constant-time Montgomery
 * powering ladder method.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 */
void fp_exp_monty(fp_t c, const fp_t a, const bn_t b);

/**
 * Computes a power of a field element by a small exponent.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the basis.
 * @param[in] b				- the exponent.
 */
void fp_exp_dig(fp_t c, const fp_t a, dig_t b);

/**
 * Tests if a prime field element is a quadratic residue.
 *
 * @param[in] a				- the prime field element to test.
 * @return 1 if the argument is even, 0 otherwise.
 */
int fp_is_sqr(const fp_t a);

/**
 * Extracts the square root of a prime field element. Computes c = sqrt(a). The
 * other square root is the negation of c.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element.
 * @return					- 1 if there is a square root, 0 otherwise.
 */
int fp_srt(fp_t c, const fp_t a);

/**
 * Tests if a prime field element is a cubic residue.
 *
 * @param[in] a				- the prime field element to test.
 * @return 1 if the argument is even, 0 otherwise.
 */
int fp_is_cub(const fp_t a);

/**
 * Extracts the cube root of a prime field element. Computes c = crt(a). The
 * other cube root is the square of c.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the prime field element.
 * @return					- 1 if there is a cube root, 0 otherwise.
 */
int fp_crt(fp_t c, const fp_t a);

#endif /* !RLC_FP_H */
