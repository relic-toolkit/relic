/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2014 RELIC Authors
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
 * Interface of the low-level prime extension field arithmetic module.
 *
 * @ingroup fpx
 */

#ifndef RLC_FPX_LOW_H
#define RLC_FPX_LOW_H

#include "relic_fpx.h"
#include "relic_fp_low.h"

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Adds two quadratic extension field elements of the same size.
 * Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp2_addn_low(fp2_t c, const fp2_t a, const fp2_t b);

/**
 * Adds two quadratic extension field elements of the same size with integrated
 * modular reduction. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp2_addm_low(fp2_t c, const fp2_t a, const fp2_t b);

/**
 * Adds two double-precision quadratic extension field elements of the same
 * size. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp2_addd_low(dv2_t c, dv2_t a, dv2_t b);

/**
 * Adds two double-precision quadratic extension field elements of the same size
 * and corrects the result by conditionally adding 2^(RLC_FP_DIGS * RLC_WSIZE) * p.
 * Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp2_addc_low(dv2_t c, dv2_t a, dv2_t b);

/**
 * Subtracts a quadratic extension field element from another of the same size.
 * Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element.
 * @param[in] b				- the field element to subtract.
 */
void fp2_subn_low(fp2_t c, const fp2_t a, const fp2_t b);

/**
 * Subtracts a quadratic extension field element from another of the same size
 * with integrated modular reduction. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element.
 * @param[in] b				- the field element to subtract.
 */
void fp2_subm_low(fp2_t c, const fp2_t a, const fp2_t b);

/**
 * Subtracts a double-precision quadratic extension field element from another
 * of the same size. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp2_subd_low(dv2_t c, dv2_t a, dv2_t b);

/**
 * Subtracts a double-precision quadratic extension field element from another
 * of the same size and  corrects the result by conditionally adding
 * 2^(RLC_FP_DIGS * RLC_WSIZE) * p. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp2_subc_low(dv2_t c, dv2_t a, dv2_t b);

/**
 * Doubles a quadratic extension field element. Computes c = a + a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 */
void fp2_dbln_low(fp2_t c, const fp2_t a);

/**
 * Doubles a quadratic extension field element with integrated modular
 * reduction. Computes c = a + a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to double.
 */
void fp2_dblm_low(fp2_t c, const fp2_t a);

/**
 * Multiplies a quadratic extension field element by the quadratic
 * non-residue. Computes c = a * E.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to multiply.
 */
void fp2_norm_low(fp2_t c, const fp2_t a);

/**
 * Multiplies a double-precision quadratic extension field element by the
 * quadratic non-residue. Computes c = a * E.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to multiply.
 */
void fp2_nord_low(dv2_t c, dv2_t a);

/**
 * Multiplies a double-length prime field element below p * R by a small
 * digit, by doubling and adding over the bits of the digit with fp_addc_low(),
 * as the quadratic extension needs for non-residues other than -1. Computes
 * c = a * digit mod p * R. The result must not overlap the input.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the double-length digit vector to multiply.
 * @param[in] digit			- the small digit to multiply.
 */
void fp2_mul1_low(dig_t *c, const dig_t *a, dig_t digit);

/**
 * Multiplies two quadratic extension field elements of the same size.
 * Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp2_muln_low(dv2_t c, const fp2_t a, const fp2_t b);

/**
 * Multiplies two quadratic extension field elements of the same size with
 * embedded modular reduction. Computes c = (a * b) mod p.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp2_mulm_low(fp2_t c, const fp2_t a, const fp2_t b);

/**
 * Squares a quadratic extension element. Computes c = a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp2_sqrn_low(dv2_t c, const fp2_t a);

/**
 * Squares a quadratic extension field element with integrated modular
 * reduction. Computes c = (a * a) mod p.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp2_sqrm_low(fp2_t c, const fp2_t a);

/**
 * Reduces a quadratic extension element modulo the configured prime p.
 * Computes c = a mod p.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to reduce.
 */
void fp2_rdcn_low(fp2_t c, dv2_t a);

/**
 * Reduces a vector of quadratic extension elements modulo the configured prime
 * p at once. Computes c_i = a_i mod p for 0 <= i < n.
 *
 * @param[out] c			- the results.
 * @param[in] a				- the digit vectors to reduce.
 * @param[in] n				- the number of elements.
 */
void fp2_rdcv_low(fp2_t *c, dv2_t *a, int n);

/**
 * Adds two cubic extension field elements of the same size.
 * Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp3_addn_low(fp3_t c, const fp3_t a, const fp3_t b);

/**
 * Adds two cubic extension field elements of the same size with integrated
 * modular reduction. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp3_addm_low(fp3_t c, const fp3_t a, const fp3_t b);

/**
 * Adds two double-precision cubic extension field elements of the same
 * size. Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp3_addd_low(dv3_t c, dv3_t a, dv3_t b);

/**
 * Adds two double-precision cubic extension field elements of the same size
 * and corrects the result by conditionally adding 3^(RLC_FP_DIGS * RLC_WSIZE) * p.
 * Computes c = a + b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp3_addc_low(dv3_t c, dv3_t a, dv3_t b);

/**
 * Subtracts a cubic extension field element from another of the same size.
 * Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element.
 * @param[in] b				- the field element to subtract.
 */
void fp3_subn_low(fp3_t c, const fp3_t a, const fp3_t b);

/**
 * Subtracts a cubic extension field element from another of the same size
 * with integrated modular reduction. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element.
 * @param[in] b				- the field element to subtract.
 */
void fp3_subm_low(fp3_t c, const fp3_t a, const fp3_t b);

/**
 * Subtracts a double-precision cubic extension field element from another
 * of the same size. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp3_subd_low(dv3_t c, dv3_t a, dv3_t b);

/**
 * Subtracts a double-precision cubic extension field element from another
 * of the same size and  corrects the result by conditionally adding
 * 3^(RLC_FP_DIGS * RLC_WSIZE) * p. Computes c = a - b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to add.
 * @param[in] b				- the second field element to add.
 */
void fp3_subc_low(dv3_t c, dv3_t a, dv3_t b);

/**
 * Doubles a cubic extension field element. Computes c = a + a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 */
void fp3_dbln_low(fp3_t c, const fp3_t a);

/**
 * Doubles a cubic extension field element with integrated modular
 * reduction. Computes c = a + a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to double.
 */
void fp3_dblm_low(fp3_t c, const fp3_t a);

/**
 * Multiplies a double-precision cubic extension field element by the
 * cubic non-residue. Computes c = a * E.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to multiply.
 */
void fp3_nord_low(dv3_t c, dv3_t a);

/**
 * Multiplies two cubic extension field elements of the same size.
 * Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp3_muln_low(dv3_t c, const fp3_t a, const fp3_t b);

/**
 * Multiplies two cubic extension elements of the same size and corrects
 * the result by adding (2^(RLC_FP_DIGS * RLC_WSIZE) * p)/4. This function should
 * be used when the RLC_FP_ROOM optimization is detected. Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp3_mulc_low(dv3_t c, const fp3_t a, const fp3_t b);

/**
 * Multiplies two cubic extension field elements of the same size with
 * embedded modular reduction. Computes c = (a * b) mod p.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp3_mulm_low(fp3_t c, const fp3_t a, const fp3_t b);

/**
 * Squares a cubic extension element. Computes c = a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp3_sqrn_low(dv3_t c, const fp3_t a);

/**
 * Squares a cubic extension field element with integrated modular
 * reduction. Computes c = (a * a) mod p.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp3_sqrm_low(fp3_t c, const fp3_t a);

/**
 * Reduces a cubic extension element modulo the configured prime p.
 * Computes c = a mod p.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the digit vector to reduce.
 */
void fp3_rdcn_low(fp3_t c, dv3_t a);

/**
 * Reduces a vector of cubic extension elements modulo the configured prime
 * p at once. Computes c_i = a_i mod p for 0 <= i < n.
 *
 * @param[out] c			- the results.
 * @param[in] a				- the digit vectors to reduce.
 * @param[in] n				- the number of elements.
 */
void fp3_rdcv_low(fp3_t *c, dv3_t *a, int n);

/**
 * Multiplies two octic extension field elements of the same size.
 * Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp8_muln_low(dv8_t c, const fp8_t a, const fp8_t b);

/**
 * Squares an octic extension field element. Computes c = a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp8_sqrn_low(dv8_t c, const fp8_t a);

/**
 * Multiplies two sextadecic extension field elements of the same size.
 * Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp16_muln_low(dv16_t c, const fp16_t a, const fp16_t b);

/**
 * Squares a sextadecic extension field element. Computes c = a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp16_sqrn_low(dv16_t c, const fp16_t a);

/**
 * Multiplies two 24-degree extension field elements of the same size.
 * Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp24_muln_low(dv24_t c, const fp24_t a, const fp24_t b);

/**
 * Squares a 24-degree extension field element. Computes c = a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp24_sqrn_low(dv24_t c, const fp24_t a);

/**
 * Multiplies two dodecic extension field elements of the same size.
 * Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the first field element to multiply.
 * @param[in] b				- the second field element to multiply.
 */
void fp12_muln_low(dv12_t c, const fp12_t a, const fp12_t b);

/**
 * Multiplies a dodecic extension field element by a sparse one, as given by
 * the lines of a pairing on the configured twist. Computes c = a * b.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the dense field element.
 * @param[in] b				- the sparse field element.
 */
void fp12_muld_low(dv12_t c, const fp12_t a, const fp12_t b);

/**
 * Squares a dodecic extension field element. Computes c = a * a.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp12_sqrn_low(dv12_t c, const fp12_t a);

/**
 * Computes the terms of a cyclotomic squaring of a dodecic extension field
 * element: for each pair (x, y) of (a_00, a_11), (a_01, a_12) and
 * (a_10, a_02), the products x^2 + E * y^2 and 2 * x * y, where E is the
 * non-residue, without reduction. They go to the positions of the
 * coefficients of the square they define: c_00 and c_11, c_02 and c_10 (with
 * 2 * x * y times E), c_01 and c_12. Compressed squaring skips the first
 * pair and leaves c_00 and c_11 untouched. In a Residue Number System, where
 * unreduced sums have room, the terms t are combined with a into the whole
 * unreduced square, c_0j = 3 * t_0j - 2 * a_0j and c_1j = 3 * t_1j + 2 * a_1j,
 * so that each squaring is reduced once and chains of them do not grow.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 * @param[in] pck			- the flag to compute compressed squaring.
 */
void fp12_sqrc_low(dv12_t c, const fp12_t a, int pck);

/**
 * Computes the terms of a cyclotomic squaring of a 24-degree extension field
 * element, as fp12_sqrc_low() does with coefficients in Fp4: for each pair
 * (x, y) of (a_00, a_01), (a_20, a_21) and (a_10, a_11), the products
 * x^2 + v * y^2 and 2 * x * y, where v is the generator of Fp4, go to c_00
 * and c_01, c_11 and c_10 (with 2 * x * y times v), c_20 and c_21. In a
 * Residue Number System, they are combined with a into the whole unreduced
 * square, so that each squaring is reduced once.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp24_sqrc_low(dv24_t c, const fp24_t a);

/**
 * Computes the terms of a cyclotomic squaring of a 48-degree extension field
 * element, as fp12_sqrc_low() does with coefficients in Fp8 and v the
 * generator of Fp8 as the non-residue.
 *
 * @param[out] c			- the result.
 * @param[in] a				- the field element to square.
 */
void fp48_sqrc_low(dv48_t c, const fp48_t a);

#endif /* !RLC_FPX_LOW_H */
