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

// Retires word I - 1 in Z0 (stored at C when RDC != 1, Montgomery-reduced
// otherwise), then adds aI x B into [Z1:Z9, Z0].
.macro FP_MULM_ROW I, A, IA, B, C, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
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
.macro FP_MULM_LOW A, IA, B, C, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
	FP_MULM_ROW	1, \A, \IA, \B, \C, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, \RDC
	FP_MULM_ROW	2, \A, \IA, \B, \C, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P, \RDC
	FP_MULM_ROW	3, \A, \IA, \B, \C, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P, \RDC
	FP_MULM_ROW	4, \A, \IA, \B, \C, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P, \RDC
	FP_MULM_ROW	5, \A, \IA, \B, \C, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P, \RDC
	FP_MULM_ROW	6, \A, \IA, \B, \C, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, \RDC
	FP_MULM_ROW	7, \A, \IA, \B, \C, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P, \RDC
	FP_MULM_ROW	8, \A, \IA, \B, \C, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, \RDC
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
