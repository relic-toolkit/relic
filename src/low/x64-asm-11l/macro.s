/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
 * Implementation of low-level prime field multiplication.
 *
 * @ingroup fp
 */

#if FP_PRIME == 672
/* CP6-672, the Cocks-Pinch prime with embedding degree 6. */
#define P0	0xAAAAAAAAB69E6DCB
#define P1	0xAAAAAAAD47EDE1A6
#define P2	0x155555CD7FA7A5F8
#define P3	0x31555CF4F24050ED
#define P4	0x7A0067B8303EEB4B
#define P5	0xC20AB5B9A7CDA7F2
#define P6	0x43EC9CFE1549FD59
#define P7	0x9A7991563C5E468D
#define P8	0xBF9E0FEFD5921162
#define P9	0xF28BFFB0C610FB10
#define P10	0x000000009401FF90
#define U0	0x3DDEBD583B76B01D
#define BAR	0xDD64CB651AE50CA8
#define BARS	31
#define BARJ	10
#else
#error "x64-asm-11l supports only FP_PRIME = 672."
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

/*
 * Stack frame of the multiplication and reduction functions. With 11 digits,
 * the accumulator takes 12 registers, the multiplier takes rdx and one more
 * register is left for the partial products, so the operand b, the pointers
 * and the constants live on the stack.
 */
#define BCPY	0(%rsp)
#define APTR	88(%rsp)
#define CPTR	96(%rsp)
#define ZEROS	104(%rsp)
#define ONES	112(%rsp)
#define CARRY	120(%rsp)
#define FRAME	128
/* The squaring functions also keep the 22 words of a^2 on the stack. */
#define SBUF	128(%rsp)
#define SFRAME	304

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

// [Z0:Z11] <- a0 x b, with a pointer to a in A.
.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T
	movq	\A, %rdx
	movq	0(%rdx), %rdx
	mulx	0+\B, \Z0, \Z1
	xorq	\T, \T
	mulx	8+\B, \T, \Z2
	adox	\T, \Z1
	mulx	16+\B, \T, \Z3
	adox	\T, \Z2
	mulx	24+\B, \T, \Z4
	adox	\T, \Z3
	mulx	32+\B, \T, \Z5
	adox	\T, \Z4
	mulx	40+\B, \T, \Z6
	adox	\T, \Z5
	mulx	48+\B, \T, \Z7
	adox	\T, \Z6
	mulx	56+\B, \T, \Z8
	adox	\T, \Z7
	mulx	64+\B, \T, \Z9
	adox	\T, \Z8
	mulx	72+\B, \T, \Z10
	adox	\T, \Z9
	mulx	80+\B, \T, \Z11
	adox	\T, \Z10
	adox	ZEROS, \Z11
.endm

// [Z0:Z10, X] <- [Z0:Z10, CARRY] + rdx x M, where the free register X turns into
// the top word and CARRY is zero unless the prime fills the top bit.
// Needs CF = OF = 0 on entry.
.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, X, T, M
	mulx	0+\M, \T, \X
	adox	\T, \Z0
	adox	\X, \Z1
	mulx	8+\M, \T, \X
	adcx	\T, \Z1
	adox	\X, \Z2
	mulx	16+\M, \T, \X
	adcx	\T, \Z2
	adox	\X, \Z3
	mulx	24+\M, \T, \X
	adcx	\T, \Z3
	adox	\X, \Z4
	mulx	32+\M, \T, \X
	adcx	\T, \Z4
	adox	\X, \Z5
	mulx	40+\M, \T, \X
	adcx	\T, \Z5
	adox	\X, \Z6
	mulx	48+\M, \T, \X
	adcx	\T, \Z6
	adox	\X, \Z7
	mulx	56+\M, \T, \X
	adcx	\T, \Z7
	adox	\X, \Z8
	mulx	64+\M, \T, \X
	adcx	\T, \Z8
	adox	\X, \Z9
	mulx	72+\M, \T, \X
	adcx	\T, \Z9
	adox	\X, \Z10
	mulx	80+\M, \T, \X
	adcx	\T, \Z10
	adox	ZEROS, \X
	adcx	CARRY, \X
.endm

// [Z1:Z11] <- ([Z0:Z11] + (Z0 x U0 mod 2^64) x M) / 2^64, freeing Z0. The low
// word cancels, so its carry is Z0 != 0, which adding all-ones to Z0 yields.
// With Z11 blank, the top word is zero on entry and is left in Z0.
// Needs CF = OF = 0 on entry.
.macro MULRDC Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T, M
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T
	mulx	0+\M, \T, \T
	adcx	ONES, \Z0
	adox	\T, \Z1
	mulx	8+\M, \T, \Z0
	adcx	\T, \Z1
	adox	\Z0, \Z2
	mulx	16+\M, \T, \Z0
	adcx	\T, \Z2
	adox	\Z0, \Z3
	mulx	24+\M, \T, \Z0
	adcx	\T, \Z3
	adox	\Z0, \Z4
	mulx	32+\M, \T, \Z0
	adcx	\T, \Z4
	adox	\Z0, \Z5
	mulx	40+\M, \T, \Z0
	adcx	\T, \Z5
	adox	\Z0, \Z6
	mulx	48+\M, \T, \Z0
	adcx	\T, \Z6
	adox	\Z0, \Z7
	mulx	56+\M, \T, \Z0
	adcx	\T, \Z7
	adox	\Z0, \Z8
	mulx	64+\M, \T, \Z0
	adcx	\T, \Z8
	adox	\Z0, \Z9
	mulx	72+\M, \T, \Z0
	adcx	\T, \Z9
	adox	\Z0, \Z10
	mulx	80+\M, \T, \Z0
	adcx	\T, \Z10
.ifb \Z11
	adox	ZEROS, \Z0
	adcx	ZEROS, \Z0
.else
	adox	\Z0, \Z11
	adcx	ZEROS, \Z11
.endif
.endm

// Final correction: stores [C:Z0:Z10] - p if it does not borrow and [Z0:Z10]
// otherwise at the pointer in CPTR. C is blank when the input is below 2^704.
.macro FINALC Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, C
	movq	CPTR, %rdx
	movq	\Z0, 0(%rdx)
	movq	\Z1, 8(%rdx)
	movq	\Z2, 16(%rdx)
	movq	\Z3, 24(%rdx)
	movq	\Z4, 32(%rdx)
	movq	\Z5, 40(%rdx)
	movq	\Z6, 48(%rdx)
	movq	\Z7, 56(%rdx)
	movq	\Z8, 64(%rdx)
	movq	\Z9, 72(%rdx)
	movq	\Z10, 80(%rdx)
	subq	p0(%rip), \Z0
	sbbq	p1(%rip), \Z1
	sbbq	p2(%rip), \Z2
	sbbq	p3(%rip), \Z3
	sbbq	p4(%rip), \Z4
	sbbq	p5(%rip), \Z5
	sbbq	p6(%rip), \Z6
	sbbq	p7(%rip), \Z7
	sbbq	p8(%rip), \Z8
	sbbq	p9(%rip), \Z9
	sbbq	p10(%rip), \Z10
.ifnb \C
	sbbq	$0, \C
.endif
	cmovc	0(%rdx), \Z0
	cmovc	8(%rdx), \Z1
	cmovc	16(%rdx), \Z2
	cmovc	24(%rdx), \Z3
	cmovc	32(%rdx), \Z4
	cmovc	40(%rdx), \Z5
	cmovc	48(%rdx), \Z6
	cmovc	56(%rdx), \Z7
	cmovc	64(%rdx), \Z8
	cmovc	72(%rdx), \Z9
	cmovc	80(%rdx), \Z10
	movq	\Z0, 0(%rdx)
	movq	\Z1, 8(%rdx)
	movq	\Z2, 16(%rdx)
	movq	\Z3, 24(%rdx)
	movq	\Z4, 32(%rdx)
	movq	\Z5, 40(%rdx)
	movq	\Z6, 48(%rdx)
	movq	\Z7, 56(%rdx)
	movq	\Z8, 64(%rdx)
	movq	\Z9, 72(%rdx)
	movq	\Z10, 80(%rdx)
.endm

// [Z0:Z10] <- [Z0:Z10]/2^704 mod p, at most p, by eleven Montgomery steps.
// Needs CF = OF = 0 on entry.
.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T, P
	MULRDC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, , \T, \P
	MULRDC	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, , \T, \P
	MULRDC	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, , \T, \P
	MULRDC	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, , \T, \P
	MULRDC	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, , \T, \P
	MULRDC	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, , \T, \P
	MULRDC	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, , \T, \P
	MULRDC	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, , \T, \P
	MULRDC	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, , \T, \P
	MULRDC	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, , \T, \P
	MULRDC	\Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, , \T, \P
.endm

// [Z0:Z10] += [0+H:80+H].
.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, H
	addq	0+\H, \Z0
	adcq	8+\H, \Z1
	adcq	16+\H, \Z2
	adcq	24+\H, \Z3
	adcq	32+\H, \Z4
	adcq	40+\H, \Z5
	adcq	48+\H, \Z6
	adcq	56+\H, \Z7
	adcq	64+\H, \Z8
	adcq	72+\H, \Z9
	adcq	80+\H, \Z10
.endm

// c <- a/2^704 mod p for a = 0+A < pR, with c at the pointer in CPTR: reduce
// the low half to at most p, add the high half, which is below p, and subtract
// p once. The low half stays below 2^704 at each step, so no carry leaves the
// accumulator.
// A must not be based on Z0..Z10 or T.
.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T, P
	xorq	\T, \T
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	56+\A, \Z7
	movq	64+\A, \Z8
	movq	72+\A, \Z9
	movq	80+\A, \Z10
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, 88+\A
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10
.endm

// a^2 for a = 0+A, computing each cross product once, with A and O based on
// %rsp. With RDC = 0, the 22 words of a^2 go to the pointer in CPTR. With
// RDC = 1, the low eleven words stay in [Z0:Z10] and the high eleven go to
// 88+O. O is 22 words of scratch.
.macro SQRN A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, RDC
	// The cross products a_i x a_j for i < j go to words 1..20 of O. Word w
	// accumulates in Z(w mod 11) and is stored once no later row adds to it.
	// [Z1:Z10, Z0] <- a0 x [a1:a10]
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
	mulx	64+\A, \T0, \Z9
	adcq	\T0, \Z8
	mulx	72+\A, \T0, \Z10
	adcq	\T0, \Z9
	mulx	80+\A, \T0, \Z0
	adcq	\T0, \Z10
	adcq	$0, \Z0
	movq	\Z1, 8+\O
	movq	\Z2, 16+\O

	// words 3..12 += a1 x [a2:a10]
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
	adox	\T1, \Z9
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z10
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z10
	adox	\T1, \Z0
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	adcq	$0, \Z1
	movq	\Z3, 24+\O
	movq	\Z4, 32+\O

	// words 5..13 += a2 x [a3:a10]
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
	adox	\T1, \Z9
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z10
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z10
	adox	\T1, \Z0
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	adcq	$0, \Z2
	movq	\Z5, 40+\O
	movq	\Z6, 48+\O

	// words 7..14 += a3 x [a4:a10]
	movq	24+\A, %rdx
	xorq	\Z3, \Z3
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z10
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z10
	adox	\T1, \Z0
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	adcq	$0, \Z3
	movq	\Z7, 56+\O
	movq	\Z8, 64+\O

	// words 9..15 += a4 x [a5:a10]
	movq	32+\A, %rdx
	xorq	\Z4, \Z4
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z10
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z10
	adox	\T1, \Z0
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	adcq	$0, \Z4
	movq	\Z9, 72+\O
	movq	\Z10, 80+\O

	// words 11..16 += a5 x [a6:a10]
	movq	40+\A, %rdx
	xorq	\Z5, \Z5
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	adcq	$0, \Z5
	movq	\Z0, 88+\O
	movq	\Z1, 96+\O

	// words 13..17 += a6 x [a7:a10]
	movq	48+\A, %rdx
	xorq	\Z6, \Z6
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	adcq	$0, \Z6
	movq	\Z2, 104+\O
	movq	\Z3, 112+\O

	// words 15..18 += a7 x [a8:a10]
	movq	56+\A, %rdx
	xorq	\Z7, \Z7
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	adcq	$0, \Z7
	movq	\Z4, 120+\O
	movq	\Z5, 128+\O

	// words 17..19 += a8 x [a9:a10]
	movq	64+\A, %rdx
	xorq	\Z8, \Z8
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	adcq	$0, \Z8
	movq	\Z6, 136+\O
	movq	\Z7, 144+\O

	// words 19..20 += a9 x [a10:a10]
	movq	72+\A, %rdx
	xorq	\Z9, \Z9
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	adcq	$0, \Z9
	movq	\Z8, 152+\O
	movq	\Z9, 160+\O

	// Doubles the cross products and adds the squares a_k^2 at word 2k, word by
	// word, with CF carrying the doubling and OF the squares. %rdx takes each
	// word that is stored.
	movq	0+\A, %rdx
	mulx	%rdx, \T0, \T1
.if \RDC != 1
	movq	CPTR, \Z0
	movq	\T0, 0(\Z0)
.else
	movq	\T0, \Z0
.endif
	xorq	%rdx, %rdx
.if \RDC != 1
	movq	8+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 8(\Z0)
	movq	8+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	16+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 16(\Z0)
	movq	24+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 24(\Z0)
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	32+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 32(\Z0)
	movq	40+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 40(\Z0)
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	48+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 48(\Z0)
	movq	56+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 56(\Z0)
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	64+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 64(\Z0)
	movq	72+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 72(\Z0)
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	80+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 80(\Z0)
	movq	88+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 88(\Z0)
	movq	48+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	96+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 96(\Z0)
	movq	104+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 104(\Z0)
	movq	56+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	112+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 112(\Z0)
	movq	120+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 120(\Z0)
	movq	64+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	128+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 128(\Z0)
	movq	136+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 136(\Z0)
	movq	72+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	144+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 144(\Z0)
	movq	152+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 152(\Z0)
	movq	80+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	160+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 160(\Z0)
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 168(\Z0)
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
	movq	72+\O, \Z9
	adcx	\Z9, \Z9
	adox	\T1, \Z9
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	80+\O, \Z10
	adcx	\Z10, \Z10
	adox	\T0, \Z10
	movq	88+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 88+\O
	movq	48+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	96+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 96+\O
	movq	104+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 104+\O
	movq	56+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	112+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 112+\O
	movq	120+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 120+\O
	movq	64+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	128+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 128+\O
	movq	136+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 136+\O
	movq	72+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	144+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 144+\O
	movq	152+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 152+\O
	movq	80+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	160+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 160+\O
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 168+\O
.endif

.endm

// c <- a^2 (RDC = 0) or a^2/2^704 mod p (RDC = 1) for a = 0+A, with c at the
// pointer in CPTR and a^2 < pR when RDC = 1. A and O are as in SQRN.
.macro FP_SQR_LOW A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC
	SQRN	\A, \O, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \RDC
.if \RDC == 1
	// The low half reduces to at most p and the high half is below p.
	xorq	\T0, \T0
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, 88+\O
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10
.endif
.endm

// Interleaved Montgomery multiplication after MULM, rotating the accumulator
// over Z0..Z11. With RDC = 0, it stores the double-precision product instead.
.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T, P, RDC
.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z0, 0(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T, \P
.endif

	// z += a1 x b
	movq	\A, %rdx
	movq	8(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z1, 8(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T, \P
.endif

	// z += a2 x b
	movq	\A, %rdx
	movq	16(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z2, 16(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T, \P
.endif

	// z += a3 x b
	movq	\A, %rdx
	movq	24(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z3, 24(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T, \P
.endif

	// z += a4 x b
	movq	\A, %rdx
	movq	32(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z4, 32(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T, \P
.endif

	// z += a5 x b
	movq	\A, %rdx
	movq	40(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z5, 40(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T, \P
.endif

	// z += a6 x b
	movq	\A, %rdx
	movq	48(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z6, 48(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T, \P
.endif

	// z += a7 x b
	movq	\A, %rdx
	movq	56(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z7, 56(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T, \P
.endif

	// z += a8 x b
	movq	\A, %rdx
	movq	64(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z8, 64(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T, \P
.endif

	// z += a9 x b
	movq	\A, %rdx
	movq	72(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z9, 72(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T, \P
.endif

	// z += a10 x b
	movq	\A, %rdx
	movq	80(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z10, 80(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T, \P
.endif

.if \RDC != 1
	movq	\Z11, 88(%rdx)
	movq	\Z0, 96(%rdx)
	movq	\Z1, 104(%rdx)
	movq	\Z2, 112(%rdx)
	movq	\Z3, 120(%rdx)
	movq	\Z4, 128(%rdx)
	movq	\Z5, 136(%rdx)
	movq	\Z6, 144(%rdx)
	movq	\Z7, 152(%rdx)
	movq	\Z8, 160(%rdx)
	movq	\Z9, 168(%rdx)
.else
	FINALC	\Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9
.endif
.endm
