/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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

#if FP_PRIME == 575
#define P0	0xF1E5CEF00AD97EFB
#define P1	0x86CBB9BA813C985D
#define P2	0x52064509AC3491BF
#define P3	0x5E1D4944218EA2D8
#define P4	0x7514F41A6C701871
#define P5	0x22696C9FB7A0951F
#define P6	0x6137D053AA030071
#define P7	0x392BFDD23348B6A2
#define P8	0x553D402AE2D5E4BC
#define U0	0x5A2DD38E5D1B23CD
#define BAR	0xC0363EEEA936D2F5
#define BARS	62
#define BARJ	8
#elif FP_PRIME == 569
#define P0	0xBBD3F32002E191D3
#define P1	0x2DC3A7B07CECAA81
#define P2	0x19DB69EB4976E975
#define P3	0x1D2ECA8F0498A59D
#define P4	0x28081F9DC91FAF54
#define P5	0xD2649EBC650544C3
#define P6	0xFE3BB690BDCF4F4B
#define P7	0x2C99CC114CD71608
#define P8	0x011B4A027E91038F
#define U0	0xBBF153EF2B9A11A5
#define BAR	0xE756F2FC1E32E048
#define BARS	56
#define BARJ	8
#else
#error "x64-asm-9l supports FP_PRIME = 569 or 575 only."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

/*
 * FP2_MUL0_LOW with RDC = 1 keeps the real part as a signed value in (-p, 2p),
 * which only fits RLC_FP_DIGS digits when 2p < 2^575, that is, p < 2^574.
 */
#if P8 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

/*
 * FP2_SQR_LOW with RDC = 1 multiplies by a0 - a1 + p < 2p with interleaved
 * reduction, whose intermediate values stay below 2^64 x (3p) and must fit
 * RLC_FP_DIGS + 1 digits. This needs 3p < 2^576, which holds for both primes.
 */
#if P8 >= 0x5555555555555555
#error "FP2_SQR_LOW needs 3p < 2^576."
#endif

/* The Fp2 functions read both coordinates from one contiguous vector. */
#if defined(FP_QNRES) && ALLOC == AUTO
#define FP2_ASM
#endif

#if defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif

.text

.macro ADD1 i, j
	movq	8*\i(%rsi), %r10
	adcq	$0, %r10
	movq	%r10, 8*\i(%rdi)
	.if \i - \j
		ADD1 "(\i + 1)", \j
	.endif
.endm

.macro ADDN i, j
	movq	8*\i(%rdx), %r11
	adcq	8*\i(%rsi), %r11
	movq	%r11, 8*\i(%rdi)
	.if \i - \j
		ADDN "(\i + 1)", \j
	.endif
.endm

.macro SUB1 i, j
	movq	8*\i(%rsi),%r10
	sbbq	$0, %r10
	movq	%r10,8*\i(%rdi)
	.if \i - \j
		SUB1 "(\i + 1)", \j
	.endif
.endm

.macro SUBN i, j
	movq	8*\i(%rsi), %r8
	sbbq	8*\i(%rdx), %r8
	movq	%r8, 8*\i(%rdi)
	.if \i - \j
		SUBN "(\i + 1)", \j
	.endif
.endm

.macro DBLN i, j
	movq	8*\i(%rsi), %r8
	adcq	%r8, %r8
	movq	%r8, 8*\i(%rdi)
	.if \i - \j
		DBLN "(\i + 1)", \j
	.endif
.endm

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10
	movq	0+\A, %rdx
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
	mulx	64+\B, \Z10, \Z9
	adox	\Z10, \Z8
	adox	%rax, \Z9
.endm

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
	movq	$0, %rax
	adcx	%rax, \Z9
.endm

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
	sbbq	$0, \T0
.endm

// Final correction
.macro FINALC Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1
	push	%rdi
	movq	\Z9, \Z8
	push	\Z9
	movq	\Z0, \T0
	push	\Z0
	movq	\Z1, \T1
	push	\Z1
	movq	\Z2, %rcx
	movq	\Z3, %rdx
	movq	\Z4, %rdi
	movq	\Z5, \Z9
	movq	\Z6, \Z1
	movq	\Z7, \Z0
	subq	p0(%rip), \Z8
	sbbq	p1(%rip), \T0
	sbbq	p2(%rip), \T1
	sbbq	p3(%rip), %rcx
	sbbq	p4(%rip), %rdx
	sbbq	p5(%rip), %rdi
	sbbq	p6(%rip), \Z9
	sbbq	p7(%rip), \Z1
	sbbq	p8(%rip), \Z0
	cmovnc  \Z1, \Z6
	popq	\Z1
	cmovnc	\Z0, \Z7
	popq	\Z0
	cmovnc  \Z9, \Z5
	popq	\Z9
	cmovnc	\Z8, \Z9
	cmovnc	\T0, \Z0
	cmovnc	\T1, \Z1
	cmovnc	%rcx, \Z2
	cmovnc	%rdx, \Z3
	cmovnc	%rdi, \Z4
	popq	%rdi
	movq	\Z9, 0(%rdi)
	movq	\Z0, 8(%rdi)
	movq	\Z1, 16(%rdi)
	movq	\Z2, 24(%rdi)
	movq	\Z3, 32(%rdi)
	movq	\Z4, 40(%rdi)
	movq	\Z5, 48(%rdi)
	movq	\Z6, 56(%rdi)
	movq	\Z7, 64(%rdi)
.endm

// Montgomery step on a window with no word above it:
// [Z1:Z8, Z0] <- ([Z0:Z8] + (Z0 x u0 mod 2^64) x p)/2^64.
// The window stays below 2^576 for p < 2^575, so no carry leaves it.
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

// [Z0:Z8] += [H0:H8], registers or memory.
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

// c <- a/2^576 mod p for a = 0+A < pR: reduce the low half to at most p, add
// the high half, which is below p, and subtract p once. A must not be based
// on Z0..Z8, T0, T1 or %rdx; T0, T1 and T2 must differ from %rcx, %rdx and
// %rdi, and T2 may be the base of A.
.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, T2, P
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
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 72+\A, 80+\A, 88+\A, 96+\A, 104+\A, 112+\A, 120+\A, 128+\A, 136+\A
	FINALC	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \Z0, \T1, \T2
.endm

// c <- a^2 at 0+C, with a = 0+A, computing each cross product once. Word k of
// the cross products lives in R(k mod 10), and words 1 to 6, whose registers
// are reused, go through 8+S to 48+S. C may equal S, but not overlap A.
// A, C and S must not be based on R0..R9, T0, T1 or %rdx.
.macro SQRN A, C, S, R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, T0, T1
	// [R1:R9] <- a0 x [a1:a8]
	movq	0+\A, %rdx
	mulx	8+\A, \R1, \R2
	mulx	16+\A, \T0, \R3
	addq	\T0, \R2
	mulx	24+\A, \T0, \R4
	adcq	\T0, \R3
	mulx	32+\A, \T0, \R5
	adcq	\T0, \R4
	mulx	40+\A, \T0, \R6
	adcq	\T0, \R5
	mulx	48+\A, \T0, \R7
	adcq	\T0, \R6
	mulx	56+\A, \T0, \R8
	adcq	\T0, \R7
	mulx	64+\A, \T0, \R9
	adcq	\T0, \R8
	adcq	$0, \R9
	movq	\R1, 8+\S
	movq	\R2, 16+\S

	// words 3 to 10 += a1 x [a2:a8]
	movq	8+\A, %rdx
	xorq	\R0, \R0
	mulx	16+\A, \T0, \T1
	adcx	\T0, \R3
	adox	\T1, \R4
	mulx	24+\A, \T0, \T1
	adcx	\T0, \R4
	adox	\T1, \R5
	mulx	32+\A, \T0, \T1
	adcx	\T0, \R5
	adox	\T1, \R6
	mulx	40+\A, \T0, \T1
	adcx	\T0, \R6
	adox	\T1, \R7
	mulx	48+\A, \T0, \T1
	adcx	\T0, \R7
	adox	\T1, \R8
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R8
	adox	\T1, \R9
	mulx	64+\A, \T0, \T1
	adcx	\T0, \R9
	adox	\T1, \R0
	adcq	$0, \R0
	movq	\R3, 24+\S
	movq	\R4, 32+\S

	// words 5 to 11 += a2 x [a3:a8]
	movq	16+\A, %rdx
	xorq	\R1, \R1
	mulx	24+\A, \T0, \T1
	adcx	\T0, \R5
	adox	\T1, \R6
	mulx	32+\A, \T0, \T1
	adcx	\T0, \R6
	adox	\T1, \R7
	mulx	40+\A, \T0, \T1
	adcx	\T0, \R7
	adox	\T1, \R8
	mulx	48+\A, \T0, \T1
	adcx	\T0, \R8
	adox	\T1, \R9
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R9
	adox	\T1, \R0
	mulx	64+\A, \T0, \T1
	adcx	\T0, \R0
	adox	\T1, \R1
	adcq	$0, \R1
	movq	\R5, 40+\S
	movq	\R6, 48+\S

	// words 7 to 12 += a3 x [a4:a8]
	movq	24+\A, %rdx
	xorq	\R2, \R2
	mulx	32+\A, \T0, \T1
	adcx	\T0, \R7
	adox	\T1, \R8
	mulx	40+\A, \T0, \T1
	adcx	\T0, \R8
	adox	\T1, \R9
	mulx	48+\A, \T0, \T1
	adcx	\T0, \R9
	adox	\T1, \R0
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R0
	adox	\T1, \R1
	mulx	64+\A, \T0, \T1
	adcx	\T0, \R1
	adox	\T1, \R2
	adcq	$0, \R2

	// words 9 to 13 += a4 x [a5:a8]
	movq	32+\A, %rdx
	xorq	\R3, \R3
	mulx	40+\A, \T0, \T1
	adcx	\T0, \R9
	adox	\T1, \R0
	mulx	48+\A, \T0, \T1
	adcx	\T0, \R0
	adox	\T1, \R1
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R1
	adox	\T1, \R2
	mulx	64+\A, \T0, \T1
	adcx	\T0, \R2
	adox	\T1, \R3
	adcq	$0, \R3

	// words 11 to 14 += a5 x [a6:a8]
	movq	40+\A, %rdx
	xorq	\R4, \R4
	mulx	48+\A, \T0, \T1
	adcx	\T0, \R1
	adox	\T1, \R2
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R2
	adox	\T1, \R3
	mulx	64+\A, \T0, \T1
	adcx	\T0, \R3
	adox	\T1, \R4
	adcq	$0, \R4

	// words 13 to 15 += a6 x [a7:a8]
	movq	48+\A, %rdx
	xorq	\R5, \R5
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R3
	adox	\T1, \R4
	mulx	64+\A, \T0, \T1
	adcx	\T0, \R4
	adox	\T1, \R5
	adcq	$0, \R5

	// [R5:R6] += a7 x a8
	movq	56+\A, %rdx
	mulx	64+\A, \T0, \R6
	addq	\T0, \R5
	adcq	$0, \R6

	// c <- 2 x [words 1 to 16] + [a0^2:a8^2]
	movq	0+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	\T0, 0+\C
	xorq	\T0, \T0
	movq	8+\S, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 8+\C
	movq	8+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	16+\S, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 16+\C
	movq	24+\S, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 24+\C
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	32+\S, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 32+\C
	movq	40+\S, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 40+\C
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	48+\S, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 48+\C
	adcx	\R7, \R7
	adox	\T1, \R7
	movq	\R7, 56+\C
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R8, \R8
	adox	\T0, \R8
	movq	\R8, 64+\C
	adcx	\R9, \R9
	adox	\T1, \R9
	movq	\R9, 72+\C
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R0, \R0
	adox	\T0, \R0
	movq	\R0, 80+\C
	adcx	\R1, \R1
	adox	\T1, \R1
	movq	\R1, 88+\C
	movq	48+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R2, \R2
	adox	\T0, \R2
	movq	\R2, 96+\C
	adcx	\R3, \R3
	adox	\T1, \R3
	movq	\R3, 104+\C
	movq	56+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R4, \R4
	adox	\T0, \R4
	movq	\R4, 112+\C
	adcx	\R5, \R5
	adox	\T1, \R5
	movq	\R5, 120+\C
	movq	64+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R6, \R6
	adox	\T0, \R6
	movq	\R6, 128+\C
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 136+\C
.endm

// c <- a^2 (RDC = 0) or a^2/2^576 mod p (RDC = 1), for a = 0+A based on %rsi.
// RDC = 0 writes 0+C and needs 56 bytes of scratch at S; RDC = 1 writes
// 0(%rdi), which may alias a, needs 144 bytes at S and reuses %rsi. T0 and T1
// must differ from %rsi and %rdi, and T1 from %rcx.
.macro FP_SQR_LOW A, C, S, R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, T0, T1, P, RDC
.if \RDC != 1
	SQRN	\A, \C, \S, \R0, \R1, \R2, \R3, \R4, \R5, \R6, \R7, \R8, \R9, \T0, \T1
.else
	// The low half reduces to at most p and the high half is below p.
	SQRN	\A, \S, \S, \R0, \R1, \R2, \R3, \R4, \R5, \R6, \R7, \R8, \R9, \T0, \T1
	FP_RDCN_LOW	\S, \R0, \R1, \R2, \R3, \R4, \R5, \R6, \R7, \R8, \R9, \T1, %rsi, \P
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif
	
	// [r9:r14, r8] <- z += 2 x a01 x a1
	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
.endif

	// [r10:r14, r8:r9] <- z += 2 x a02 x a1
	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r14, r8:r10] <- z += 2 x a03 x a1
	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r14, r8:r11] <- z += 2 x a04 x a1
	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z += 2 x a05 x a1
	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z += 2 x a06 x a1
	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z += 2 x a07 x a1
	xorq	\Z6, \Z6
	movq	56+\A, %rdx
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z += 2 x a07 x a1
	xorq	\Z7, \Z7
	movq	64+\A, %rdx
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\Z8, 64(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T0
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z9, 72(%rdi)
	movq	\Z0, 80(%rdi)
	movq	\Z1, 88(%rdi)
	movq	\Z2, 96(%rdi)
	movq	\Z3, 104(%rdi)
	movq	\Z4, 112(%rdi)
	movq	\Z5, 120(%rdi)
	movq	\Z6, 128(%rdi)
	movq	\Z7, 136(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
	movq	72+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z9
	sbbq	$0, \Z0

	// [r9:r14, r8] <- z = a0 x b01 - a1 x b11 + z 
	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \B
	movq	80+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	// [r10:r14, r8:r9] <- z = a0 x b02 - a1 x b12 + z 
	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \B
	movq	88+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	// [r11:r14, r8:r10] <- z = a0 x b03 - a1 x b13 + z
	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	96+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	// [r12:r14, r8:r11] <- z = a0 x b04 - a1 x b14 + z 
	movq	32+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	104+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	// [r13:r14, r8:r12] <- z = a0 x b05 - a1 x b15 + z 
	movq	40+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	112+\A, %rdx
	MULSUB	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z5, \Z5
	btq		$63, \Z4
	sbbq	$0, \Z5

	movq	48+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
	movq	120+\A, %rdx
	MULSUB	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	xorq	\Z6, \Z6
	btq		$63, \Z5
	sbbq	$0, \Z6

	movq	56+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
	movq	128+\A, %rdx
	MULSUB	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	xorq	\Z7, \Z7
	btq		$63, \Z6
	sbbq	$0, \Z7

	movq	64+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
	movq	136+\A, %rdx
	MULSUB	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z8, 64(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T0
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif
	btq		$63, \Z7

	// Correction if result < 0
	push	%rdi
	push	\Z7
	push	\Z6
	push	\Z5
    movq 	$0, \Z8
    movq 	$0, \T0
    movq 	$0, \T1
    movq 	$0, \Z5
    movq	$0, \Z6
	movq	$0, \Z7
    movq	$0, %rdx
	movq	$0, %rcx
	movq	$0, %rdi
    cmovc	p0(%rip), \Z8
    cmovc	p1(%rip), \T0
    cmovc	p2(%rip), \T1
    cmovc	p3(%rip), \Z5
    cmovc	p4(%rip), \Z6
    cmovc	p5(%rip), \Z7
	cmovc	p6(%rip), %rdx
	cmovc	p7(%rip), %rcx
	cmovc	p8(%rip), %rdi
	addq	\Z8, \Z9
	adcq	\T0, \Z0
	adcq	\T1, \Z1
	adcq	\Z5, \Z2
	popq	\Z5
	adcq	\Z6, \Z3
	popq	\Z6
	adcq	\Z7, \Z4
	popq	\Z7
	adcq	%rdx, \Z5
	adcq	%rcx, \Z6
	adcq	%rdi, \Z7
	popq	%rdi
.if \RDC != 1
	movq	\Z9, 72(%rdi)
	movq	\Z0, 80(%rdi)
	movq	\Z1, 88(%rdi)
	movq	\Z2, 96(%rdi)
	movq	\Z3, 104(%rdi)
	movq	\Z4, 112(%rdi)
	movq	\Z5, 120(%rdi)
	movq	\Z6, 128(%rdi)
	movq	\Z7, 136(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
	movq	72+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif

	// [r9:r14, r8] <- z = a0 x b11 + a1 x b01 + z		
	xorq	\Z0, \Z0 
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, 72+\B
	movq	80+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
.endif

	// [r10:r14, r8:r9] <- z = a0 x b12 + a1 x b02 + z		
	xorq	\Z1, \Z1 
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, 72+\B
	movq	88+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r14, r8:r10] <- z = a0 x b13 + a1 x b03 + z		
	xorq	\Z2, \Z2 
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, 72+\B
	movq	96+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r14, r8:r11] <- z = a0 x b14 + a1 x b04 + z		
	xorq	\Z3, \Z3 
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 72+\B
	movq	104+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z = a0 x b15 + a1 x b05 + z
	xorq	\Z4, \Z4 
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 72+\B
	movq	112+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 72+\B
	movq	120+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	xorq	\Z6, \Z6
	movq	56+\A, %rdx
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 72+\B
	movq	128+\A, %rdx
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\Z7, \Z7
	movq	64+\A, %rdx
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 72+\B
	movq	136+\A, %rdx
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\Z8, 64(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T0
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z9, 72(%rdi)
	movq	\Z0, 80(%rdi)
	movq	\Z1, 88(%rdi)
	movq	\Z2, 96(%rdi)
	movq	\Z3, 104(%rdi)
	movq	\Z4, 112(%rdi)
	movq	\Z5, 120(%rdi)
	movq	\Z6, 128(%rdi)
	movq	\Z7, 136(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.endif
.endm

// c <- a x b in Fp2 with u^2 = -1, for a = 0+A based on %rcx and b = 0+B
// based on %rsp. RDC = 0: c0 at %rdi and c1 at the pointer in 8+S. RDC = 1:
// c0 at %rdi and c1 at 72(%rdi), reduced, where c may alias a or b. S is 11
// words of scratch.
.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
	movq	%rcx, 0+\S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 0
	movq	0+\S, %rcx
	movq	8+\S, %rdi
	MULM	\A, 72+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 0
.else
	// c1 goes to the scratch space, since c0 still reads a1 and b1.
	movq	%rdi, 8+\S
	leaq	16+\S, %rdi
	MULM	\A, 72+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 1
	movq	0+\S, %rcx
	movq	8+\S, %rdi
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 1
	movq	16+\S, \Z0
	movq	24+\S, \Z1
	movq	32+\S, \Z2
	movq	40+\S, \Z3
	movq	48+\S, \Z4
	movq	56+\S, \Z5
	movq	64+\S, \Z6
	movq	72+\S, \Z7
	movq	80+\S, \Z8
	movq	\Z0, 72(%rdi)
	movq	\Z1, 80(%rdi)
	movq	\Z2, 88(%rdi)
	movq	\Z3, 96(%rdi)
	movq	\Z4, 104(%rdi)
	movq	\Z5, 112(%rdi)
	movq	\Z6, 120(%rdi)
	movq	\Z7, 128(%rdi)
	movq	\Z8, 136(%rdi)
.endif
.endm

// c <- a^2 in Fp2 with u^2 = -1, for a = 0+A based on %rcx:
// c0 = (a0 + a1) x (a0 - a1 + p), c1 = 2 x a0 x a1. RDC = 0: c0 at %rdi and
// c1 at the pointer in 216+S. RDC = 1: c0 at %rdi and c1 at 72(%rdi),
// reduced, where c may alias a. S is 29 words of scratch.
.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
	// [0+S] <- a0 + a1, [72+S] <- a0 - a1 + p, [144+S] <- 2 x a0
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	56+\A, \Z7
	movq	64+\A, \Z8
	movq	\Z0, \Z9
	addq	72+\A, \Z9
	movq	\Z9, 0+\S
	movq	\Z1, \Z9
	adcq	80+\A, \Z9
	movq	\Z9, 8+\S
	movq	\Z2, \Z9
	adcq	88+\A, \Z9
	movq	\Z9, 16+\S
	movq	\Z3, \Z9
	adcq	96+\A, \Z9
	movq	\Z9, 24+\S
	movq	\Z4, \Z9
	adcq	104+\A, \Z9
	movq	\Z9, 32+\S
	movq	\Z5, \Z9
	adcq	112+\A, \Z9
	movq	\Z9, 40+\S
	movq	\Z6, \Z9
	adcq	120+\A, \Z9
	movq	\Z9, 48+\S
	movq	\Z7, \Z9
	adcq	128+\A, \Z9
	movq	\Z9, 56+\S
	movq	\Z8, \Z9
	adcq	136+\A, \Z9
	movq	\Z9, 64+\S
	movq	\Z0, \Z9
	addq	\Z9, \Z9
	movq	\Z9, 144+\S
	movq	\Z1, \Z9
	adcq	\Z9, \Z9
	movq	\Z9, 152+\S
	movq	\Z2, \Z9
	adcq	\Z9, \Z9
	movq	\Z9, 160+\S
	movq	\Z3, \Z9
	adcq	\Z9, \Z9
	movq	\Z9, 168+\S
	movq	\Z4, \Z9
	adcq	\Z9, \Z9
	movq	\Z9, 176+\S
	movq	\Z5, \Z9
	adcq	\Z9, \Z9
	movq	\Z9, 184+\S
	movq	\Z6, \Z9
	adcq	\Z9, \Z9
	movq	\Z9, 192+\S
	movq	\Z7, \Z9
	adcq	\Z9, \Z9
	movq	\Z9, 200+\S
	movq	\Z8, \Z9
	adcq	\Z9, \Z9
	movq	\Z9, 208+\S
	subq	72+\A, \Z0
	sbbq	80+\A, \Z1
	sbbq	88+\A, \Z2
	sbbq	96+\A, \Z3
	sbbq	104+\A, \Z4
	sbbq	112+\A, \Z5
	sbbq	120+\A, \Z6
	sbbq	128+\A, \Z7
	sbbq	136+\A, \Z8
	addq	0+\P, \Z0
	adcq	8+\P, \Z1
	adcq	16+\P, \Z2
	adcq	24+\P, \Z3
	adcq	32+\P, \Z4
	adcq	40+\P, \Z5
	adcq	48+\P, \Z6
	adcq	56+\P, \Z7
	adcq	64+\P, \Z8
	movq	\Z0, 72+\S
	movq	\Z1, 80+\S
	movq	\Z2, 88+\S
	movq	\Z3, 96+\S
	movq	\Z4, 104+\S
	movq	\Z5, 112+\S
	movq	\Z6, 120+\S
	movq	\Z7, 128+\S
	movq	\Z8, 136+\S

	// c1 first: it is the last reader of a, and c0 only reads the scratch.
.if \RDC != 1
	movq	%rdi, 224+\S
	movq	216+\S, %rdi
.else
	addq	$72, %rdi
.endif
	MULM	144+\S, 72+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP_MUL_LOW	144+\S, 72+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, \RDC
.if \RDC != 1
	movq	224+\S, %rdi
.else
	subq	$72, %rdi
.endif
	MULM	0+\S, 72+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP_MUL_LOW	0+\S, 72+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, \RDC
.endm
