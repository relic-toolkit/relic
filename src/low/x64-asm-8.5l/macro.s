/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2022 RELIC Authors
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

#include "relic_fp_low.h"

/**
 * @file
 *
 * Macros and constants for the low-level prime field arithmetic.
 *
 * Elements of the 544-bit prime field are stored in N = 9 limbs and the top
 * limb uses only 32 bits. Double-length values use the half-limb convention:
 * they occupy 2N - 1 = 17 limbs and are kept below p * 2^544, the largest
 * multiple of p * 2^512 that fits in 17 limbs. The constants _P0.._P8 hold
 * p * 2^32, so that adding or subtracting p * 2^544 only touches limbs 8..16.
 * The limb at index 17 of a double-length vector is never read.
 *
 * @ingroup fp
 */

#if FP_PRIME == 544
#define P0	0x45A58C1085E14411
#define P1	0x39A5CD02C6F4B6B6
#define P2	0x9B3A84FA363BCD25
#define P3	0x049031AE4CA1D271
#define P4	0xF33E58FE66943943
#define P5	0xC15B47AA5AA84626
#define P6	0xC05E7CC0373D9B1A
#define P7	0x9299F1C803DDD5D7
#define P8	0x00000000BB9DFD54
#define U0	0x9935F6572883D30F
#define BAR	0xAEA74ECCD65CD043
#define BARS	31
#define BARJ	8
/* p * 2^32, used for corrections modulo p * 2^544 on double-length values. */
#define _P0	0x85E1441100000000
#define _P1	0xC6F4B6B645A58C10
#define _P2	0x363BCD2539A5CD02
#define _P3	0x4CA1D2719B3A84FA
#define _P4	0x66943943049031AE
#define _P5	0x5AA84626F33E58FE
#define _P6	0x373D9B1AC15B47AA
#define _P7	0x03DDD5D7C05E7CC0
#define _P8	0xBB9DFD549299F1C8
#else
#error "x64-asm-8.5l supports only FP_PRIME == 544."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

/*
 * The Fp2 functions read both coordinates from one contiguous vector, which
 * only automatic allocation without padding between coordinates guarantees.
 */
#if ALLOC == AUTO && ALIGN < 16
#define FP2_ASM
#endif

#if defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif

.text

.macro ADD1 i j
	movq	8*\i(%rsi), %r10
	adcq	$0, %r10
	movq	%r10, 8*\i(%rdi)
	.if \i - \j
		ADD1 "(\i + 1)" \j
	.endif
.endm

.macro ADDN i j
	movq	8*\i(%rdx), %r11
	adcq	8*\i(%rsi), %r11
	movq	%r11, 8*\i(%rdi)
	.if \i - \j
		ADDN "(\i + 1)" \j
	.endif
.endm

.macro SUB1 i j
	movq	8*\i(%rsi),%r10
	sbbq	$0, %r10
	movq	%r10,8*\i(%rdi)
	.if \i - \j
		SUB1 "(\i + 1)" \j
	.endif
.endm

.macro SUBN i j
	movq	8*\i(%rsi), %r8
	sbbq	8*\i(%rdx), %r8
	movq	%r8, 8*\i(%rdi)
	.if \i - \j
		SUBN "(\i + 1)" \j
	.endif
.endm

.macro DBLN i j
	movq	8*\i(%rsi), %r8
	adcq	%r8, %r8
	movq	%r8, 8*\i(%rdi)
	.if \i - \j
		DBLN "(\i + 1)" \j
	.endif
.endm

// Shifts the vector at (%rdi) right by one bit in place, limbs i to j - 1, with
// X holding limb i on entry and Y as a temporary. Limb j is read, not written.
.macro RSH1D i j X Y
	movq	8*(\i + 1)(%rdi), \Y
	shrdq	$1, \Y, \X
	movq	\X, 8*\i(%rdi)
	.if \j - \i - 1
		RSH1D "(\i + 1)" \j \Y \X
	.endif
.endm

// Loads limb I of the operand A into %rdx. With IND = 1, A is a memory slot
// holding a pointer to the operand; otherwise A addresses the operand.
.macro LDA A, I, IND
.if \IND
	movq	\A, %rdx
	movq	8*\I(%rdx), %rdx
.else
	movq	8*\I+\A, %rdx
.endif
.endm

// [Z0:Z9] <- a0 x B, with T0 as a temporary. Clears %rax, CF and OF.
.macro MULM A, IA, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0
	LDA	\A, 0, \IA
	mulx	0+\B, \Z0, \Z1
	xorq	%rax, %rax
	mulx	8+\B, \Z3, \Z2
	adox	\Z3, \Z1
	mulx	16+\B, \Z4, \Z3
	adox	\Z4, \Z2
	mulx	24+\B, \Z5, \Z4
	adox	\Z5, \Z3
	mulx	32+\B, \Z6, \Z5
	adox	\Z6, \Z4
	mulx	40+\B, \Z7, \Z6
	adox	\Z7, \Z5
	mulx	48+\B, \Z8, \Z7
	adox	\Z8, \Z6
	mulx	56+\B, \Z9, \Z8
	adox	\Z9, \Z7
	mulx	64+\B, \T0, \Z9
	adox	\T0, \Z8
	adox	%rax, \Z9
.endm

// [Z0:Z9] += %rdx x M. Needs CF = OF = 0 and %rax = 0 on entry.
.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, M
	mulx	0+\M, \T1, \T0
	adox	\T1, \Z0
	adox	\T0, \Z1
	mulx	8+\M, \T1, \T0
	adcx	\T1, \Z1
	adox	\T0, \Z2
	mulx	16+\M, \T1, \T0
	adcx	\T1, \Z2
	adox	\T0, \Z3
	mulx	24+\M, \T1, \T0
	adcx	\T1, \Z3
	adox	\T0, \Z4
	mulx	32+\M, \T1, \T0
	adcx	\T1, \Z4
	adox	\T0, \Z5
	mulx	40+\M, \T1, \T0
	adcx	\T1, \Z5
	adox	\T0, \Z6
	mulx	48+\M, \T1, \T0
	adcx	\T1, \Z6
	adox	\T0, \Z7
	mulx	56+\M, \T1, \T0
	adcx	\T1, \Z7
	adox	\T0, \Z8
	mulx	64+\M, \T1, \T0
	adcx	\T1, \Z8
	adox	\T0, \Z9
	adcx	%rax, \Z9
.endm

// [Z0:Z9] -= %rdx x M, subtracting the odd limbs of the product first and
// the even limbs next, so that each pass is a single borrow chain.
.macro MULSUB Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, M
	mulx	8+\M, \T1, \T0
	subq	\T1, \Z1
	sbbq	\T0, \Z2
	mulx	24+\M, \T1, \T0
	sbbq	\T1, \Z3
	sbbq	\T0, \Z4
	mulx	40+\M, \T1, \T0
	sbbq	\T1, \Z5
	sbbq	\T0, \Z6
	mulx	56+\M, \T1, \T0
	sbbq	\T1, \Z7
	sbbq	\T0, \Z8
	sbbq	$0, \Z9
	mulx	0+\M, \T1, \T0
	subq	\T1, \Z0
	sbbq	\T0, \Z1
	mulx	16+\M, \T1, \T0
	sbbq	\T1, \Z2
	sbbq	\T0, \Z3
	mulx	32+\M, \T1, \T0
	sbbq	\T1, \Z4
	sbbq	\T0, \Z5
	mulx	48+\M, \T1, \T0
	sbbq	\T1, \Z6
	sbbq	\T0, \Z7
	mulx	64+\M, \T1, \T0
	sbbq	\T1, \Z8
	sbbq	\T0, \Z9
.endm

// Final correction: stores [Z0:Z8] - p at C if there is no borrow, [Z0:Z8]
// otherwise. The input is kept in memory to select from, as there are not
// enough free registers for a copy.
.macro FINALC Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, C
	movq	\Z0, 0(\C)
	movq	\Z1, 8(\C)
	movq	\Z2, 16(\C)
	movq	\Z3, 24(\C)
	movq	\Z4, 32(\C)
	movq	\Z5, 40(\C)
	movq	\Z6, 48(\C)
	movq	\Z7, 56(\C)
	movq	\Z8, 64(\C)
	subq	p0(%rip), \Z0
	sbbq	p1(%rip), \Z1
	sbbq	p2(%rip), \Z2
	sbbq	p3(%rip), \Z3
	sbbq	p4(%rip), \Z4
	sbbq	p5(%rip), \Z5
	sbbq	p6(%rip), \Z6
	sbbq	p7(%rip), \Z7
	sbbq	p8(%rip), \Z8
	cmovc	0(\C), \Z0
	cmovc	8(\C), \Z1
	cmovc	16(\C), \Z2
	cmovc	24(\C), \Z3
	cmovc	32(\C), \Z4
	cmovc	40(\C), \Z5
	cmovc	48(\C), \Z6
	cmovc	56(\C), \Z7
	cmovc	64(\C), \Z8
	movq	\Z0, 0(\C)
	movq	\Z1, 8(\C)
	movq	\Z2, 16(\C)
	movq	\Z3, 24(\C)
	movq	\Z4, 32(\C)
	movq	\Z5, 40(\C)
	movq	\Z6, 48(\C)
	movq	\Z7, 56(\C)
	movq	\Z8, 64(\C)
.endm

// Montgomery step on a window with no word above it:
// [Z1:Z8, Z0] <- ([Z0:Z8] + (Z0 x u0 mod 2^64) x p)/2^64.
// The window stays below 2^576 for p < 2^544, so no carry leaves it.
.macro RDCSTEP Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P
	movq	$U0, %rdx
	imulq	\Z0, %rdx
	xorq	\T0, \T0
	mulx	0+\P, \T0, \T1
	adox	\T0, \Z0
	adox	\T1, \Z1
	mulx	8+\P, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	16+\P, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	24+\P, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	32+\P, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	40+\P, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	48+\P, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	56+\P, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	64+\P, \T0, \T1
	adcx	\T0, \Z8
	// Z0 is zero here, so this cannot overflow.
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

// [Z0:Z8] <- [Z0:Z8]/2^576 mod p, at most p, by nine Montgomery steps.
.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	RDCSTEP	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	RDCSTEP	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	RDCSTEP	\Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endm

// [Z0:Z8] += [H0:H8], registers, memory or immediates.
.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, H0, H1, H2, H3, H4, H5, H6, H7, H8
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
	adcq	\H5, \Z5
	adcq	\H6, \Z6
	adcq	\H7, \Z7
	adcq	\H8, \Z8
.endm

// c <- a/2^576 mod p for a double-length a = 0+A of 17 digits: reduce the low
// nine digits to at most p, add the high eight digits, which are below
// 2^512 < p, and subtract p once. The result goes to C, a register other than
// %rdx; T0 and T1 must differ from %rdx.
.macro FP_RDCN_LOW A, C, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	56+\A, \Z7
	movq	64+\A, \Z8
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 72+\A, 80+\A, 88+\A, 96+\A, 104+\A, 112+\A, 120+\A, 128+\A, $0
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \C
.endm

// a^2 for a = 0+A, computing each cross product once. With RDC = 0, the 18
// words of a^2 go to O. With RDC = 1, the low nine words stay in [Z0:Z8] and
// the high nine go to 72+O. Uses %rax and %rdx.
.macro SQRN A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, RDC
	// The cross products a_i x a_j for i < j go to words 1..16 of O. Word w
	// accumulates in Z(w mod 9) and is stored once no later row adds to it.
	// [Z1:Z8, Z0] <- a0 x [a1:a8]
	movq	0+\A, %rdx
	mulx	8+\A, \Z1, \Z2
	mulx	16+\A, \T0, \Z3
	addq	\T0, \Z2
	mulx	24+\A, \T0, \Z4
	adcq	\T0, \Z3
	mulx	32+\A, \T0, \Z5
	adcq	\T0, \Z4
	mulx	40+\A, \T0, \Z6
	adcq	\T0, \Z5
	mulx	48+\A, \T0, \Z7
	adcq	\T0, \Z6
	mulx	56+\A, \T0, \Z8
	adcq	\T0, \Z7
	mulx	64+\A, \T0, \Z0
	adcq	\T0, \Z8
	adcq	$0, \Z0
	movq	\Z1, 8+\O
	movq	\Z2, 16+\O

	// words 3..10 += a1 x [a2:a8]
	movq	8+\A, %rdx
	xorq	\Z1, \Z1
	mulx	16+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z0
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	adcq	$0, \Z1
	movq	\Z3, 24+\O
	movq	\Z4, 32+\O

	// words 5..11 += a2 x [a3:a8]
	movq	16+\A, %rdx
	xorq	\Z2, \Z2
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z0
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	adcq	$0, \Z2
	movq	\Z5, 40+\O
	movq	\Z6, 48+\O

	// words 7..12 += a3 x [a4:a8]
	movq	24+\A, %rdx
	xorq	\Z3, \Z3
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z0
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	adcq	$0, \Z3
	movq	\Z7, 56+\O
	movq	\Z8, 64+\O

	// words 9..13 += a4 x [a5:a8]
	movq	32+\A, %rdx
	xorq	\Z4, \Z4
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	adcq	$0, \Z4
	movq	\Z0, 72+\O
	movq	\Z1, 80+\O

	// words 11..14 += a5 x [a6:a8]
	movq	40+\A, %rdx
	xorq	\Z5, \Z5
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	adcq	$0, \Z5
	movq	\Z2, 88+\O
	movq	\Z3, 96+\O

	// words 13..15 += a6 x [a7:a8]
	movq	48+\A, %rdx
	xorq	\Z6, \Z6
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	adcq	$0, \Z6
	movq	\Z4, 104+\O
	movq	\Z5, 112+\O

	// words 15..16 += a7 x [a8:a8]
	movq	56+\A, %rdx
	xorq	\Z7, \Z7
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	adcq	$0, \Z7
	movq	\Z6, 120+\O
	movq	\Z7, 128+\O

	// Doubles the cross products and adds the squares a_k^2 at word 2k, word by
	// word, with CF carrying the doubling and OF the squares.
	movq	0+\A, %rdx
	mulx	%rdx, \T0, \T1
.if \RDC != 1
	movq	\T0, 0+\O
.else
	movq	\T0, \Z0
.endif
	xorq	%rax, %rax
.if \RDC != 1
	movq	8+\O, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 8+\O
	movq	8+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	16+\O, %rax
	adcx	%rax, %rax
	adox	\T0, %rax
	movq	%rax, 16+\O
	movq	24+\O, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 24+\O
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	32+\O, %rax
	adcx	%rax, %rax
	adox	\T0, %rax
	movq	%rax, 32+\O
	movq	40+\O, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 40+\O
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	48+\O, %rax
	adcx	%rax, %rax
	adox	\T0, %rax
	movq	%rax, 48+\O
	movq	56+\O, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 56+\O
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	64+\O, %rax
	adcx	%rax, %rax
	adox	\T0, %rax
	movq	%rax, 64+\O
.else
	movq	8+\O, \Z1
	adcx	\Z1, \Z1
	adox	\T1, \Z1
	movq	8+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	16+\O, \Z2
	adcx	\Z2, \Z2
	adox	\T0, \Z2
	movq	24+\O, \Z3
	adcx	\Z3, \Z3
	adox	\T1, \Z3
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	32+\O, \Z4
	adcx	\Z4, \Z4
	adox	\T0, \Z4
	movq	40+\O, \Z5
	adcx	\Z5, \Z5
	adox	\T1, \Z5
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	48+\O, \Z6
	adcx	\Z6, \Z6
	adox	\T0, \Z6
	movq	56+\O, \Z7
	adcx	\Z7, \Z7
	adox	\T1, \Z7
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	64+\O, \Z8
	adcx	\Z8, \Z8
	adox	\T0, \Z8
.endif
	movq	72+\O, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 72+\O
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	80+\O, %rax
	adcx	%rax, %rax
	adox	\T0, %rax
	movq	%rax, 80+\O
	movq	88+\O, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 88+\O
	movq	48+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	96+\O, %rax
	adcx	%rax, %rax
	adox	\T0, %rax
	movq	%rax, 96+\O
	movq	104+\O, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 104+\O
	movq	56+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	112+\O, %rax
	adcx	%rax, %rax
	adox	\T0, %rax
	movq	%rax, 112+\O
	movq	120+\O, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 120+\O
	movq	64+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	128+\O, %rax
	adcx	%rax, %rax
	adox	\T0, %rax
	movq	%rax, 128+\O
	movq	$0, %rax
	adcx	%rax, %rax
	adox	\T1, %rax
	movq	%rax, 136+\O
.endm

// c <- a^2 (RDC = 0) or a^2/2^576 mod p (RDC = 1), for a = 0+A, with a^2 < p x
// 2^576 when RDC = 1. With RDC = 0, O is c and it must not overlap a. With
// RDC = 1, O is 18 words of scratch and the result goes to C, a register.
.macro FP_SQR_LOW A, O, C, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P, RDC
	SQRN	\A, \O, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \RDC
.if \RDC == 1
	// The low half reduces to at most p and the high half is below p.
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 72+\O, 80+\O, 88+\O, 96+\O, 104+\O, 112+\O, 120+\O, 128+\O, 136+\O
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \C
.endif
.endm

// Retires word I - 1 in Z0 (stored at C when RDC != 1, Montgomery-reduced
// otherwise), then adds aI x B into [Z1:Z9, Z0].
.macro FP_MUL_ROW I, A, IA, B, C, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
.if \RDC != 1
	movq	\C, %rdx
	movq	\Z0, 8*(\I - 1)(%rdx)
.else
	// [Z0:Z9] <- z = (z0 x u0) x p + z, which clears z0
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif
	// [Z1:Z9, Z0] <- z += aI x B
	xorq	\Z0, \Z0
	LDA	\A, \I, \IA
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \B
.endm

// Montgomery multiplication (RDC = 1) or plain product (RDC != 1) of A and B
// after MULM, interleaving the reduction steps. A is read as in LDA and C is
// a memory slot holding the result pointer. With RDC = 1, the product must be
// below p * 2^576 (for instance, A and B below 2^544), so that the result
// before FINALC is below 2p.
.macro FP_MUL_LOW A, IA, B, C, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
	FP_MUL_ROW	1, \A, \IA, \B, \C, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, \RDC
	FP_MUL_ROW	2, \A, \IA, \B, \C, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P, \RDC
	FP_MUL_ROW	3, \A, \IA, \B, \C, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P, \RDC
	FP_MUL_ROW	4, \A, \IA, \B, \C, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P, \RDC
	FP_MUL_ROW	5, \A, \IA, \B, \C, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P, \RDC
	FP_MUL_ROW	6, \A, \IA, \B, \C, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, \RDC
	FP_MUL_ROW	7, \A, \IA, \B, \C, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P, \RDC
	FP_MUL_ROW	8, \A, \IA, \B, \C, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, \RDC
.if \RDC != 1
	movq	\C, %rdx
	movq	\Z8, 64(%rdx)
	movq	\Z9, 72(%rdx)
	movq	\Z0, 80(%rdx)
	movq	\Z1, 88(%rdx)
	movq	\Z2, 96(%rdx)
	movq	\Z3, 104(%rdx)
	movq	\Z4, 112(%rdx)
	movq	\Z5, 120(%rdx)
	movq	\Z6, 128(%rdx)
	movq	\Z7, 136(%rdx)
.else
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T0
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
	movq	\C, %rdx
	FINALC	\Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, %rdx
.endif
.endm

// One row of c0 = a0 x b0 - a1 x B1 for u^2 = -5, with B1 = 5 x b1 below
// 2^547. The window [Z0:Z9] holds a signed value with Z0 as word I: it adds
// a0I x B0 (for I > 0), subtracts a1I x B1, reduces word I and sign-extends
// the new top word into Z0. MULSUB leaves the flags set and the signed sums
// may carry out of the top word, so CF and OF are cleared before each MULADD.
.macro FP2_MUL0_ROW I, A, IA, B0, B1, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
.if \I
	LDA	\A, \I, \IA
	xorq	%rax, %rax
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B0
.endif
	LDA	\A, "(\I + 9)", \IA
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B1
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.if \I - 8
	xorq	\Z0, \Z0
	btq	$63, \Z9
	sbbq	$0, \Z0
.endif
.endm

// c0 = (a0 x b0 - a1 x B1) / 2^576 mod p after MULM computed a00 x B0, with B1
// = 5 x b1 (so that u^2 = -5) as a 9-limb operand. The result before the
// correction lies in (-p, 2p): p is added and FINALC runs twice. Only the
// reduced variant exists: the unreduced value would need a multiple of
// p * 2^544 larger than 17 limbs to become nonnegative.
.macro FP2_MUL0_LOW A, IA, B0, B1, C, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
	FP2_MUL0_ROW	0, \A, \IA, \B0, \B1, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
	FP2_MUL0_ROW	1, \A, \IA, \B0, \B1, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
	FP2_MUL0_ROW	2, \A, \IA, \B0, \B1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
	FP2_MUL0_ROW	3, \A, \IA, \B0, \B1, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
	FP2_MUL0_ROW	4, \A, \IA, \B0, \B1, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	FP2_MUL0_ROW	5, \A, \IA, \B0, \B1, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	FP2_MUL0_ROW	6, \A, \IA, \B0, \B1, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	FP2_MUL0_ROW	7, \A, \IA, \B0, \B1, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	FP2_MUL0_ROW	8, \A, \IA, \B0, \B1, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
	addq	p0(%rip), \Z9
	adcq	p1(%rip), \Z0
	adcq	p2(%rip), \Z1
	adcq	p3(%rip), \Z2
	adcq	p4(%rip), \Z3
	adcq	p5(%rip), \Z4
	adcq	p6(%rip), \Z5
	adcq	p7(%rip), \Z6
	adcq	p8(%rip), \Z7
	movq	\C, %rdx
	FINALC	\Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, %rdx
	FINALC	\Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, %rdx
.endm

// One row of c1 = a0 x b1 + a1 x b0, with Z0 as word I and the new top word
// already cleared: adds a0I x B1 (for I > 0) and a1I x B0, then reduces word I.
.macro FP2_MUL1_ROW I, A, IA, B0, B1, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
.if \I
	LDA	\A, \I, \IA
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B1
.endif
	LDA	\A, "(\I + 9)", \IA
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B0
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.if \I - 8
	xorq	\Z0, \Z0
.endif
.endm

// c1 = (a0 x b1 + a1 x b0) / 2^576 mod p after MULM computed a00 x B1. The
// result before FINALC is below 2p. As for c0, only the reduced variant exists,
// since a0 x b1 + a1 x b0 may not fit in 17 limbs.
.macro FP2_MUL1_LOW A, IA, B0, B1, C, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
	FP2_MUL1_ROW	0, \A, \IA, \B0, \B1, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
	FP2_MUL1_ROW	1, \A, \IA, \B0, \B1, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
	FP2_MUL1_ROW	2, \A, \IA, \B0, \B1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
	FP2_MUL1_ROW	3, \A, \IA, \B0, \B1, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
	FP2_MUL1_ROW	4, \A, \IA, \B0, \B1, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	FP2_MUL1_ROW	5, \A, \IA, \B0, \B1, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	FP2_MUL1_ROW	6, \A, \IA, \B0, \B1, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	FP2_MUL1_ROW	7, \A, \IA, \B0, \B1, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	FP2_MUL1_ROW	8, \A, \IA, \B0, \B1, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
	movq	\C, %rdx
	FINALC	\Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, %rdx
.endm

// c <- a x b in Fp2 with u^2 = -5, reduced coefficient-wise, for a at the
// pointer in 0+S, b at %rcx and c at the pointer in 8+S, each holding both
// coordinates as consecutive N-digit vectors. c may alias a or b. S is 21
// words, with 16+S taking 5 x b1, 96+S taking c1 and 88+S pointing to it.
.macro FP2_MUL_LOW S, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
	// [16+S] <- 5 x b1, which is below 2^547 and fits in N digits.
	movq	$5, %rdx
	xorq	%rax, %rax
	mulx	72(%rcx), \Z0, \Z1
	mulx	80(%rcx), \Z3, \Z2
	adox	\Z3, \Z1
	mulx	88(%rcx), \Z4, \Z3
	adox	\Z4, \Z2
	mulx	96(%rcx), \Z5, \Z4
	adox	\Z5, \Z3
	mulx	104(%rcx), \Z6, \Z5
	adox	\Z6, \Z4
	mulx	112(%rcx), \Z7, \Z6
	adox	\Z7, \Z5
	mulx	120(%rcx), \Z8, \Z7
	adox	\Z8, \Z6
	mulx	128(%rcx), \Z9, \Z8
	adox	\Z9, \Z7
	mulx	136(%rcx), \T0, \Z9
	adox	\T0, \Z8
	movq	\Z0, 16+\S
	movq	\Z1, 24+\S
	movq	\Z2, 32+\S
	movq	\Z3, 40+\S
	movq	\Z4, 48+\S
	movq	\Z5, 56+\S
	movq	\Z6, 64+\S
	movq	\Z7, 72+\S
	movq	\Z8, 80+\S

	// c1 goes to the scratch space, since c0 still reads a1 and b1.
	leaq	96+\S, %rax
	movq	%rax, 88+\S
	MULM	0+\S, 1, 72(%rcx), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL1_LOW	0+\S, 1, 0(%rcx), 72(%rcx), 88+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
	MULM	0+\S, 1, 0(%rcx), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL0_LOW	0+\S, 1, 0(%rcx), 16+\S, 8+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
	movq	8+\S, %rdx
	movq	96+\S, \Z0
	movq	104+\S, \Z1
	movq	112+\S, \Z2
	movq	120+\S, \Z3
	movq	128+\S, \Z4
	movq	136+\S, \Z5
	movq	144+\S, \Z6
	movq	152+\S, \Z7
	movq	160+\S, \Z8
	movq	\Z0, 72(%rdx)
	movq	\Z1, 80(%rdx)
	movq	\Z2, 88(%rdx)
	movq	\Z3, 96(%rdx)
	movq	\Z4, 104(%rdx)
	movq	\Z5, 112(%rdx)
	movq	\Z6, 120(%rdx)
	movq	\Z7, 128(%rdx)
	movq	\Z8, 136(%rdx)
.endm

// c <- a^2 in Fp2 with u^2 = -5, reduced coefficient-wise, for a at %rcx and
// c at the pointer in 0+S, both as consecutive N-digit vectors, with
// c1 = 2 x a0 x a1 and c0 = (a0 + a1) x (a0 + 5 x (p - a1)) + 2 x c1.
// The products stay below p x 2^576: 2p x p for c1 and 2p x 6p for c0.
// c may alias a. S is 29 words, with 8+S pointing to c1.
.macro FP2_SQR_LOW S, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
	// [16+S] <- a0 + a1
	movq	0(%rcx), %rax
	addq	72(%rcx), %rax
	movq	%rax, 16+\S
	.set	k, 1
	.rept	8
	movq	8*k(%rcx), %rax
	adcq	72+8*k(%rcx), %rax
	movq	%rax, 16+8*k+\S
	.set	k, k + 1
	.endr
	// [160+S] <- 2 x a0
	movq	0(%rcx), %rax
	addq	%rax, %rax
	movq	%rax, 160+\S
	.set	k, 1
	.rept	8
	movq	8*k(%rcx), %rax
	adcq	%rax, %rax
	movq	%rax, 160+8*k+\S
	.set	k, k + 1
	.endr
	// [88+S] <- a0 + 5 x (p - a1)
	movq	0+\P, \Z0
	subq	72(%rcx), \Z0
	movq	8+\P, \Z1
	sbbq	80(%rcx), \Z1
	movq	16+\P, \Z2
	sbbq	88(%rcx), \Z2
	movq	24+\P, \Z3
	sbbq	96(%rcx), \Z3
	movq	32+\P, \Z4
	sbbq	104(%rcx), \Z4
	movq	40+\P, \Z5
	sbbq	112(%rcx), \Z5
	movq	48+\P, \Z6
	sbbq	120(%rcx), \Z6
	movq	56+\P, \Z7
	sbbq	128(%rcx), \Z7
	movq	64+\P, \Z8
	sbbq	136(%rcx), \Z8
	movq	$5, %rdx
	mulx	\Z0, \Z0, \T0
	mulx	\Z1, \Z1, \T1
	addq	\T0, \Z1
	mulx	\Z2, \Z2, \T0
	adcq	\T1, \Z2
	mulx	\Z3, \Z3, \T1
	adcq	\T0, \Z3
	mulx	\Z4, \Z4, \T0
	adcq	\T1, \Z4
	mulx	\Z5, \Z5, \T1
	adcq	\T0, \Z5
	mulx	\Z6, \Z6, \T0
	adcq	\T1, \Z6
	mulx	\Z7, \Z7, \T1
	adcq	\T0, \Z7
	mulx	\Z8, \Z8, \T0
	adcq	\T1, \Z8
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 0(%rcx), 8(%rcx), 16(%rcx), 24(%rcx), 32(%rcx), 40(%rcx), 48(%rcx), 56(%rcx), 64(%rcx)
	movq	\Z0, 88+\S
	movq	\Z1, 96+\S
	movq	\Z2, 104+\S
	movq	\Z3, 112+\S
	movq	\Z4, 120+\S
	movq	\Z5, 128+\S
	movq	\Z6, 136+\S
	movq	\Z7, 144+\S
	movq	\Z8, 152+\S

	// c1 first: it is the last reader of a, and c0 only reads the scratch.
	MULM	160+\S, 0, 72(%rcx), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP_MUL_LOW	160+\S, 0, 72(%rcx), 8+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 1
	MULM	16+\S, 0, 88+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP_MUL_LOW	16+\S, 0, 88+\S, 0+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 1

	// c0 <- c0 + 2 x c1, below 3p before two corrections.
	movq	0+\S, %rdx
	movq	0(%rdx), \Z0
	movq	8(%rdx), \Z1
	movq	16(%rdx), \Z2
	movq	24(%rdx), \Z3
	movq	32(%rdx), \Z4
	movq	40(%rdx), \Z5
	movq	48(%rdx), \Z6
	movq	56(%rdx), \Z7
	movq	64(%rdx), \Z8
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 72(%rdx), 80(%rdx), 88(%rdx), 96(%rdx), 104(%rdx), 112(%rdx), 120(%rdx), 128(%rdx), 136(%rdx)
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 72(%rdx), 80(%rdx), 88(%rdx), 96(%rdx), 104(%rdx), 112(%rdx), 120(%rdx), 128(%rdx), 136(%rdx)
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, %rdx
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, %rdx
.endm
