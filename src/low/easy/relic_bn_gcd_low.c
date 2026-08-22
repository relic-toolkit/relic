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
 * or <https://www.apache.org/licenses/>
 */

/**
 * @file
 *
 * Implementation of the low-level multiple precision integer greatest common
 * divisor functions.
 *
 * @ingroup bn
 */

#include "relic_core.h"
#include "relic_bn.h"
#include "relic_bn_low.h"
#include "relic_util.h"
#include <stddef.h>
#include "relic_dv.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Returns the number of significant digits of a digit vector.
 *
 * @param[in] a				- the digit vector.
 * @param[in] size			- the size of the digit vector.
 * @return the number of significant digits, zero if the vector is zero.
 */
static size_t bn_size_low(const dig_t *a, size_t size) {
	while (size > 0 && a[size - 1] == 0) {
		size--;
	}
	return size;
}

/**
 * Returns the number of trailing zero bits of a digit vector.
 *
 * @param[in] a				- the digit vector, must not be zero.
 * @param[in] size			- the number of significant digits.
 * @return the number of trailing zero bits.
 */
static size_t bn_ctz_low(const dig_t *a, size_t size) {
	for (size_t i = 0; i < size; i++) {
		if (a[i] != 0) {
			/* Isolating the lowest set bit turns the count into a length. */
			return i * RLC_DIG + util_bits_dig(a[i] & (~a[i] + (dig_t)1)) - 1;
		}
	}
	return 0;
}

/**
 * Shifts a digit vector to the right by an arbitrary number of bits, in place.
 *
 * @param[in,out] a			- the digit vector.
 * @param[in] size			- the number of significant digits.
 * @param[in] bits			- the number of bits to shift by.
 * @return the new number of significant digits.
 */
static size_t bn_rsh_low(dig_t *a, size_t size, size_t bits) {
	size_t digits;
	RLC_RIP(bits, digits, bits);
	dv_rshd(a, a, size, digits);
	bn_rshb_low(a, a, size, bits);
	return bn_size_low(a, size);
}

/**
 * Subtracts a shorter digit vector from a longer one, in place.
 *
 * @param[in,out] a			- the minuend, and the difference.
 * @param[in] sa			- the number of significant digits of the minuend.
 * @param[in] b				- the subtrahend, must not be larger than a.
 * @param[in] sb			- the number of significant digits of the subtrahend.
 * @return the new number of significant digits.
 */
static size_t bn_subx_low(dig_t *a, size_t sa, const dig_t *b, size_t sb) {
	dig_t carry = bn_subn_low(a, a, b, sb);

	if (sa > sb) {
		bn_sub1_low(a + sb, a + sb, carry, sa - sb);
	}
	return bn_size_low(a, sa);
}

/** Flips a sign, given that RLC_POS is 0 and RLC_NEG is 1. */
#define BN_SGN_NEG(S)	(RLC_NEG - (S))

/**
 * Adds one fixed-width sign-magnitude value into another, computing x <- x + y.
 * Both operands occupy exactly size digits, which removes all length
 * bookkeeping from the cofactor arithmetic; the caller sizes them so that no
 * carry can escape.
 *
 * @param[in,out] x			- the first operand, and the sum.
 * @param[in,out] sgx		- the sign of the first operand, and of the sum.
 * @param[in] y				- the second operand.
 * @param[in] sgy			- the sign of the second operand.
 * @param[in] size			- the width in digits of both operands.
 */
static void bn_addsig_low(dig_t *x, int *sgx, const dig_t *y, int sgy,
		size_t size) {
	if (*sgx == sgy) {
		bn_addn_low(x, x, y, size);
	} else {
		int cmp = dv_cmp(x, y, size);

		if (cmp == RLC_EQ) {
			dv_zero(x, size);
			*sgx = RLC_POS;
		} else if (cmp == RLC_GT) {
			bn_subn_low(x, x, y, size);
		} else {
			/* x <- y - x, which bn_subn_low performs in place. */
			bn_subn_low(x, y, x, size);
			*sgx = sgy;
		}
	}
}

/**
 * c <- c + a * b, for non-negative operands, as the matrix update requires.
 * The entries only ever grow, because every step matrix is [[1, q], [0, 1]] or
 * [[1, 0], [q, 1]] and so has non-negative entries.
 */
static size_t bn_mulacc_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *b,
		size_t sb, dig_t *t, size_t size) {
	dig_t carry;

	if (sa == 0 || sb == 0) {
		return bn_size_low(c, size);
	}
	/* bn_muld_low writes the product rather than accumulating into it */
	if (sa >= sb) {
		bn_muld_low(t, a, sa, b, sb, 0, sa + sb);
	} else {
		bn_muld_low(t, b, sb, a, sa, 0, sa + sb);
	}
	carry = bn_addn_low(c, c, t, sa + sb);
	if (carry) {
		bn_add1_low(c + sa + sb, c + sa + sb, carry, size - sa - sb);
	}
	return bn_size_low(c, size);
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

size_t bn_gcdn_low(dig_t *c, dig_t *a, size_t sa, dig_t *b, size_t sb) {
	size_t i;
	int cmp;

	sa = bn_size_low(a, sa);
	sb = bn_size_low(b, sb);

	/* gcd(a, 0) = a and gcd(0, b) = b, which also covers gcd(0, 0) = 0. */
	if (sa == 0 || sb == 0) {
		const dig_t *r = (sa == 0 ? b : a);
		size_t sr = (sa == 0 ? sb : sa);

		dv_copy(c, r, sr);
		return sr;
	}

	/*
	 * Binary GCD, due to Stein. Only comparison, subtraction and shifting are
	 * needed, which is what makes it the natural basic algorithm at this layer:
	 */
	sa = bn_rsh_low(a, sa, bn_ctz_low(a, sa));
	sb = bn_rsh_low(b, sb, bn_ctz_low(b, sb));

	while ((cmp = bn_cmpn_low(a, sa, b, sb)) != RLC_EQ) {
		if (cmp == RLC_GT) {
			sa = bn_subx_low(a, sa, b, sb);
			sa = bn_rsh_low(a, sa, bn_ctz_low(a, sa));
		} else {
			sb = bn_subx_low(b, sb, a, sa);
			sb = bn_rsh_low(b, sb, bn_ctz_low(b, sb));
		}
	}

	for (i = 0; i < sa; i++) {
		c[i] = a[i];
	}
	return sa;
}

size_t bn_gcde_low(dig_t *c, dig_t *d, int *sd, dig_t *a, size_t sa,
		dig_t *b, size_t sb) {
	/*
	 * A and B are the cofactors of the first working value, C and D those of
	 * the second, and a0, b0 are the operands with the common power of two
	 * removed, which the halving rule below refers to. Held on the stack at
	 * fixed width so that the signed arithmetic needs no length bookkeeping;
	 * that costs 6 * (RLC_BN_SIZE + 1) digits of frame.
	 */
	dig_t A[RLC_BN_SIZE + 2], B[RLC_BN_SIZE + 2];
	dig_t C[RLC_BN_SIZE + 2], D[RLC_BN_SIZE + 2];
	dig_t a0[RLC_BN_SIZE + 2], b0[RLC_BN_SIZE + 2];
	int sgA, sgB, sgC, sgD;
	size_t cap, shift, sx, sy, sg, sb0, sm, sc;
	uint_t rem;
	sa = bn_size_low(a, sa);
	sb = bn_size_low(b, sb);
	/* gcd(a, 0) = a with cofactor 1, gcd(0, b) = b with cofactor 0. */
	if (sa == 0 || sb == 0) {
		size_t sr = (sa == 0 ? sb : sa);
		dv_copy(c, (sa == 0 ? b : a), sr);
		d[0] = (sa == 0 || sr == 0 ? 0 : 1);
		*sd = d[0];
		return sr;
	}
	/*
	 * The extended form of the binary GCD above, following Algorithm 14.61 of
	 * the Handbook of Applied Cryptography.
	 *
	 * Unlike bn_gcdn_low this cannot require an operand to be odd, and that is
	 * not an oversight but the same asymmetry GMP has: mpn_gcd demands that one
	 * operand be odd while mpn_gcdext does not. Demanding it would let the
	 * cofactors be carried as unsigned residues modulo the odd operand, which is
	 * far cheaper, but only yields the cofactor of the *other* one. A routine
	 * that has to return the cofactor of a specific operand cannot choose which,
	 * so it has to handle either parity, which means signed cofactors and the
	 * common power of two divided out here rather than by the caller.
	 *
	 * Each working value therefore carries a pair of cofactors, and halving a
	 * value forces its cofactors to be halved too. That is only possible
	 * directly when both are even, and otherwise uses
	 *
	 *     A <- (A + b0)/2,   B <- (B - a0)/2,
	 *
	 * which leaves A*a0 + B*b0 unchanged and is exact because a0 and b0 are not
	 * both even once the common power of two has been removed: that forces
	 * A = b0 and B = a0 modulo 2 whenever the two are not both even.
	 *
	 * Only the cofactor of a is reported, as mpn_gcdext does. The other is
	 * recoverable as (c - a*d)/b by exact division, but B and D still have to be
	 * carried here, because the halving rule branches on their parity.
	 */
	cap = RLC_MAX(sa, sb) + 1;
	shift = RLC_MIN(bn_ctz_low(a, sa), bn_ctz_low(b, sb));
	sx = bn_rsh_low(a, sa, shift);
	sy = bn_rsh_low(b, sb, shift);
	dv_zero(a0, cap);
	dv_zero(b0, cap);
	dv_copy(a0, a, sx);
	dv_copy(b0, b, sy);
	sb0 = sy;
	dv_zero(A, cap);
	dv_zero(B, cap);
	dv_zero(C, cap);
	dv_zero(D, cap);
	A[0] = 1;					/* A = 1, B = 0, so x = A*a0 + B*b0 */
	D[0] = 1;					/* C = 0, D = 1, so y = C*a0 + D*b0 */
	sgA = sgB = sgC = sgD = RLC_POS;
	while (sx != 0) {
		while ((a[0] & 1) == 0) {
			sx = bn_rsh_low(a, sx, 1);
			if (((A[0] | B[0]) & 1) != 0) {
				bn_addsig_low(A, &sgA, b0, RLC_POS, cap);
				bn_addsig_low(B, &sgB, a0, RLC_NEG, cap);
			}
			bn_rsh1_low(A, A, cap);
			bn_rsh1_low(B, B, cap);
		}
		while ((b[0] & 1) == 0) {
			sy = bn_rsh_low(b, sy, 1);
			if (((C[0] | D[0]) & 1) != 0) {
				bn_addsig_low(C, &sgC, b0, RLC_POS, cap);
				bn_addsig_low(D, &sgD, a0, RLC_NEG, cap);
			}
			bn_rsh1_low(C, C, cap);
			bn_rsh1_low(D, D, cap);
		}
		if (bn_cmpn_low(a, sx, b, sy) != RLC_LT) {
			sx = bn_subx_low(a, sx, b, sy);
			bn_addsig_low(A, &sgA, C, BN_SGN_NEG(sgC), cap);
			bn_addsig_low(B, &sgB, D, BN_SGN_NEG(sgD), cap);
		} else {
			sy = bn_subx_low(b, sy, a, sx);
			bn_addsig_low(C, &sgC, A, BN_SGN_NEG(sgA), cap);
			bn_addsig_low(D, &sgD, B, BN_SGN_NEG(sgB), cap);
		}
	}
	/*
	 * Reduce the cofactor into the range mpn_gcdext produces, which is what
	 * makes the two agree rather than merely both be correct: the cofactor is
	 * only determined modulo b/gcd, and the interval |d| < b/(2*gcd) has width
	 * exactly b/gcd, so it holds one representative per class.
	 *
	 * This has to happen before the gcd is shifted back up, because that step
	 * consumes shift and sy: it turns shift from a bit count into a digit count
	 * and leaves sy holding the size of the shifted result rather than of the
	 * gcd. Running the reduction afterwards passes the divisor's size as the
	 * dividend's, which yields a zero modulus.
	 *
	 * A, B, D and a0 are dead by now and serve as scratch.
	 */
	/*
	 * m = b0 / g1, exact, into D; b still holds g1 with sy digits.
	 *
	 * bn_divn_low destroys both operands and wants all four areas at the size
	 * of the dividend plus one, so it is fed copies, exactly as bn_div_rem
	 * does. Getting that wrong is what made an earlier version of this look as
	 * though the primitive itself were at fault.
	 */
	dv_zero(A, cap + 1);
	dv_zero(B, cap + 1);
	dv_zero(D, cap + 1);
	dv_zero(a0, cap + 1);
	dv_copy(A, b0, sb0);
	dv_copy(B, b, sy);
	bn_divn_low(D, a0, A, sb0, B, sy);
	/*
	 * The quotient occupies exactly sa - sb + 1 digits and the remainder
	 * exactly sb; bn_divn_low leaves whatever it likes above those, so the
	 * extent has to be bounded here rather than scanning the whole buffer.
	 * bn_div_rem sets q->used and r->used the same way.
	 */
	sm = bn_size_low(D, sb0 - sy + 1);
	/* C mod m, into [0, m) */
	sc = bn_size_low(C, cap);
	if (bn_cmpn_low(C, sc, D, sm) != RLC_LT) {
		dv_zero(A, cap + 1);
		dv_zero(B, cap + 1);
		dv_zero(b0, cap + 1);
		dv_copy(A, C, sc);
		dv_copy(B, D, sm);
		dv_zero(C, cap);
		bn_divn_low(b0, C, A, sc, B, sm);
		sc = bn_size_low(C, sm);
		dv_zero(C + sm, cap - sm);
	}
	if (sgC == RLC_NEG && sc != 0) {
		/* the negative of a residue in [0, m) is m minus it */
		bn_subn_low(C, D, C, sm);
		sc = bn_size_low(C, sm);
		sgC = RLC_POS;
	}
	/*
	 * Centre it: take the negative representative when 2C exceeds m. The
	 * comparison is strict, which leaves C = m/2 positive and matches the
	 * S = 1 escape mpn_gcdext documents for the cases where its bound cannot
	 * be met.
	 */
	dv_zero(A, cap + 1);
	dv_copy(A, C, sc);
	A[sc] = bn_lshb_low(A, A, sc, 1);
	if (bn_cmpn_low(A, bn_size_low(A, sc + 1), D, sm) == RLC_GT) {
		bn_subn_low(C, D, C, sm);
		sc = bn_size_low(C, sm);
		sgC = RLC_NEG;
	}
	/* The gcd is y << shift; the cofactors are unaffected by that factor. */
	rem = (uint_t)(shift % RLC_DIG);
	shift /= RLC_DIG;
	dv_zero(c, shift);
	if (rem > 0) {
		c[sy + shift] = bn_lshb_low(c + shift, b, sy, rem);
		sy += (c[sy + shift] != 0);
	} else {
		dv_copy(c + shift, b, sy);
	}
	sg = sy + shift;
	dv_copy(d, C, sc);
	*sd = (sgC == RLC_NEG ? -sc : sc);
	return sg;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

size_t bn_gcdh_low(dig_t *m00, dig_t *m01, dig_t *m10, dig_t *m11, size_t *sm,
		dig_t *a, dig_t *b, size_t size) {
	dig_t *t = RLC_ALLOCA(dig_t, 5 * (size + 2));
	dig_t *num = t, *den = t + size + 2, *quo = t + 2 * (size + 2);
	dig_t *rem = t + 3 * (size + 2), *scr = t + 4 * (size + 2);
	size_t s = size / 2 + 1, sa, sb, sq, mw = (size + 1) / 2 + 1;
	size_t s00 = 1, s01 = 0, s10 = 0, s11 = 1;
	int steps = 0;

	dv_zero(m00, mw);
	dv_zero(m01, mw);
	dv_zero(m10, mw);
	dv_zero(m11, mw);
	m00[0] = 1;
	m11[0] = 1;

	if (size <= s) {
		return 0;
	}
	if ((a[size - 1] | b[size - 1]) == 0) {
		return 0;					/* not normalized, nothing to do */
	}

	sa = bn_size_low(a, size);
	sb = bn_size_low(b, size);

	/*
	 * The matrix starts at the identity and is multiplied on the right by
	 * [[1, q], [0, 1]] when a is reduced modulo b, and by [[1, 0], [q, 1]] when
	 * b is reduced modulo a. Each factor has determinant one and non-negative
	 * entries, and the two slots are never exchanged, so the product keeps both
	 * properties with no bookkeeping.
	 *
	 * This reduces both operands to s digits, which is more than the contract
	 * requires: it only asks that the difference fit s digits. Reducing further
	 * is permitted and costs the caller fewer repetitions.
	 */
	while (RLC_MAX(sa, sb) > s) {
		dig_t *big;
		const dig_t *sml;
		size_t sbig, ssml;
		if (sa == 0 || sb == 0) {
			break;
		}
		if (bn_cmpn_low(a, sa, b, sb) != RLC_LT) {
			big = a; sbig = sa; sml = b; ssml = sb;
		} else {
			big = b; sbig = sb; sml = a; ssml = sa;
		}

		/*
		 * bn_divn_low destroys both operands and may extend either by a digit
		 * while normalizing, so it is given copies with a spare digit each.
		 */
		dv_copy(num, big, sbig);
		num[sbig] = 0;
		dv_copy(den, sml, ssml);
		den[ssml] = 0;
		bn_divn_low(quo, rem, num, sbig, den, ssml);

		/*
		 * The quotient occupies exactly sbig - ssml + 1 digits and the remainder
		 * exactly ssml, with the areas above those extents left unspecified, so
		 * the sizes are bounded rather than scanned.
		 */
		sq = bn_size_low(quo, sbig - ssml + 1);
		if (sq == 0) {
			break;					/* no progress, do not loop forever */
		}

		/*
		 * A quotient wide enough to push the matrix past its documented width
		 * cannot be folded in, which happens as soon as the operands are far
		 * apart in size: reducing a full-length value by a single-digit one
		 * takes one enormous quotient. The step is abandoned before either
		 * operand is touched, so the caller sees no reduction and falls back to
		 * an elementary division, which is what mpn_gcd does with
		 * mpn_gcd_subdiv_step for the same reason.
		 */
		if ((big == a ? RLC_MAX(s00, s10) : RLC_MAX(s01, s11)) + sq + 1 > mw) {
			break;
		}

		dv_copy(big, rem, ssml);
		sbig = bn_size_low(big, ssml);
		if (big == a) {
			sa = sbig;
			s01 = bn_mulacc_low(m01, m00, s00, quo, sq, scr, mw);
			s11 = bn_mulacc_low(m11, m10, s10, quo, sq, scr, mw);
		} else {
			sb = sbig;
			s00 = bn_mulacc_low(m00, m01, s01, quo, sq, scr, mw);
			s10 = bn_mulacc_low(m10, m11, s11, quo, sq, scr, mw);
		}
		steps++;
	}
	if (steps == 0) {
		return 0;
	}
	/* clear whatever the reduction left above the significant digits */
	dv_zero(a + sa, size - sa);
	dv_zero(b + sb, size - sb);
	*sm = RLC_MAX(RLC_MAX(s00, s01), RLC_MAX(s10, s11));
	RLC_FREE(t);
	return RLC_MAX(sa, sb);
}
 