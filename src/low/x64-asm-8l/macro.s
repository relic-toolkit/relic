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

#if FP_PRIME == 455
#define P0	0xAAA00001800002AB
#define P1	0xA6C589556B2AA956
#define P2	0xB3DB9994ACE86D1B
#define P3	0x4BD93954FCB314B8
#define P4	0x3F665E3A5B1D5623
#define P5	0xA00E0F95B4920300
#define P6	0x555955557955572A
#define P7	0x0000000000000055
#define U0	0x4B3EF8137F4017FD
#define BAR	0xBFFFF700001AFFFE
#define BARS	6
#define BARJ	7
#elif FP_PRIME == 508
#define P0	0xCD1CCCF628BC1B1D
#define P1	0x6B5CC3A8F69C137A
#define P2	0x0B1B3D5304D0957E
#define P3	0x3D3F6EB93785360E
#define P4	0x91E008FC121F0707
#define P5	0xA5524C027B6231A4
#define P6	0xF420B8A16E4727D4
#define P7	0x0C33B72B87E5A44D
#define U0	0x71AA8793EFE880CB
#define BAR	0xA7D7558A6ADB59D0
#define BARS	59
#define BARJ	7
#elif FP_PRIME == 509
#define P0	0xA13D118DB8BFD2AB
#define P1	0xEE63BD076E8D9300
#define P2	0xCFCB5C6071BAD3D2
#define P3	0x626E85BF7C18A0F0
#define P4	0x32EA0103E01090BB
#define P5	0xCB8AC8495D187E8C
#define P6	0xFCEDF2B4F9C0ECF6
#define P7	0x155556FFFF39CA9B
#define U0	0x6EFA1180A5FE67FD
#define BAR	0xBFFFF1000823DF55
#define BARS	60
#define BARJ	7
#elif FP_PRIME == 510
#define P0	0xDD5F62C1A3044101
#define P1	0x393DDECB1D3C5517
#define P2	0x8E97A75A70B54410
#define P3	0xBA09F4BACE3AC558
#define P4	0x13BA8856149CDCB6
#define P5	0xB32E21F17F8B0A67
#define P6	0x5A1673FA252B4DAA
#define P7	0x31BEC371AB26D0A6
#define U0	0x766D29254B8340FF
#define BAR	0xA4ADE6F58CE7791A
#define BARS	61
#define BARJ	7
#elif FP_PRIME == 511
/* CTIDH-511, the prime selected by fp_param_set_any(). */
#define P0	0x1B81B90533C6C87B
#define P1	0xC2721BF457ACA835
#define P2	0x516730CC1F0B4F25
#define P3	0xA7AAC6C567F35507
#define P4	0x5AFBFCC69322C9CD
#define P5	0xB42D083AEDC88C42
#define P6	0xFC8AB0D15E3E4C4A
#define P7	0x65B48E8F740F89BF
#define U0	0x66C1301F632E294D
#define BAR	0xA117C7275007EB1F
#define BARS	62
#define BARJ	7
#else
#error "x64-asm-8l supports FP_PRIME = 455, 508, 509, 510 or 511 only."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

/*
 * FP2_MUL0_LOW with RDC = 1 keeps the real part as a signed value in (-p, 2p),
 * which only fits RLC_FP_DIGS digits when 2p < 2^511, that is, p < 2^510.
 */
#if P7 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

/*
 * FP2_SQR_LOW with RDC = 1 multiplies by a0 - a1 + p < 2p with interleaved
 * reduction, whose intermediate values stay below 2^64 x (3p) and must fit
 * RLC_FP_DIGS + 1 digits, so it needs 3p < 2^512.
 */
#if P7 < 0x5555555555555555
#define FP2_SQR_RDC
#endif

/* The Fp2 functions read both coordinates from one contiguous vector. */
#if defined(FP_QNRES) && ALLOC == AUTO
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

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9
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
	adox	%rax, \Z8
.endm

.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, M
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
	movq	$0, %rax
	adcx	%rax, \Z8
.endm

.macro MULSUB Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, M
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
	sbbq	$0, \Z8
	sbbq	$0, \T1
.endm

// Final correction
.macro FINALC Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1
	push	%rdi
	movq	\Z8, \Z7
	push	\Z8
	movq	\Z0, \T0
	movq	\Z1, \T1
	movq	\Z2, %rcx
	movq	\Z3, %rdx
	movq	\Z4, %rsi
	movq	\Z5, %rdi
	movq	\Z6, \Z8
	subq	p0(%rip), \Z7
	sbbq	p1(%rip), \T0
	sbbq	p2(%rip), \T1
	sbbq	p3(%rip), %rcx
	sbbq	p4(%rip), %rdx
	sbbq	p5(%rip), %rsi
	sbbq	p6(%rip), %rdi
	sbbq	p7(%rip), \Z8
	cmovnc  \Z8, \Z6
	popq	\Z8
	cmovnc	\Z7, \Z8
	cmovnc	\T0, \Z0
	cmovnc	\T1, \Z1
	cmovnc	%rcx, \Z2
	cmovnc	%rdx, \Z3
	cmovnc	%rsi, \Z4
	cmovnc	%rdi, \Z5
	popq	%rdi
	movq	\Z8, 0(%rdi)
	movq	\Z0, 8(%rdi)
	movq	\Z1, 16(%rdi)
	movq	\Z2, 24(%rdi)
	movq	\Z3, 32(%rdi)
	movq	\Z4, 40(%rdi)
	movq	\Z5, 48(%rdi)
	movq	\Z6, 56(%rdi)
.endm

// Montgomery step on a window with no word above it:
// [Z1:Z7, Z0] <- ([Z0:Z7] + (Z0 x u0 mod 2^64) x p)/2^64.
// The window stays below 2^512 for p < 2^511, so no carry leaves it.
.macro RDCSTEP Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P
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
	// Z0 is zero here, so this cannot overflow.
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

// [Z0:Z7] <- [Z0:Z7]/2^512 mod p, at most p, by eight Montgomery steps.
.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	RDCSTEP	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	RDCSTEP	\Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endm

// [Z0:Z7] += [H0:H7], registers or memory.
.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, H0, H1, H2, H3, H4, H5, H6, H7
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
	adcq	\H5, \Z5
	adcq	\H6, \Z6
	adcq	\H7, \Z7
.endm

// c <- a/2^512 mod p for a = 0+A < pR: reduce the low half to at most p, add
// the high half, which is below p, and subtract p once. A must not be based
// on Z0..Z7, T0, T1 or %rdx; T0, T1 and T2 must differ from %rcx, %rdx, %rsi
// and %rdi.
.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, T2, P
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	56+\A, \Z7
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, 64+\A, 72+\A, 80+\A, 88+\A, 96+\A, 104+\A, 112+\A, 120+\A
	FINALC	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \Z0, \T1, \T2
.endm

// c <- a^2 at 0+C, with a = 0+A, computing each cross product once. Word k of
// the cross products lives in R(k mod 9), and words 1 to 5, whose registers
// are reused, go through 8+S to 40+S. C may equal S, but not overlap A.
// A, C and S must not be based on R0..R8, T0, T1 or %rdx.
.macro SQRN A, C, S, R0, R1, R2, R3, R4, R5, R6, R7, R8, T0, T1
	// [R1:R8] <- a0 x [a1:a7]
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
	adcq	$0, \R8
	movq	\R1, 8+\S
	movq	\R2, 16+\S

	// [R3:R8, R0] += a1 x [a2:a7]
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
	adox	\T1, \R0
	adcq	$0, \R0
	movq	\R3, 24+\S
	movq	\R4, 32+\S

	// [R5:R8, R0:R1] += a2 x [a3:a7]
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
	adox	\T1, \R0
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R0
	adox	\T1, \R1
	adcq	$0, \R1
	movq	\R5, 40+\S

	// [R7:R8, R0:R2] += a3 x [a4:a7]
	movq	24+\A, %rdx
	xorq	\R2, \R2
	mulx	32+\A, \T0, \T1
	adcx	\T0, \R7
	adox	\T1, \R8
	mulx	40+\A, \T0, \T1
	adcx	\T0, \R8
	adox	\T1, \R0
	mulx	48+\A, \T0, \T1
	adcx	\T0, \R0
	adox	\T1, \R1
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R1
	adox	\T1, \R2
	adcq	$0, \R2

	// [R0:R3] += a4 x [a5:a7]
	movq	32+\A, %rdx
	xorq	\R3, \R3
	mulx	40+\A, \T0, \T1
	adcx	\T0, \R0
	adox	\T1, \R1
	mulx	48+\A, \T0, \T1
	adcx	\T0, \R1
	adox	\T1, \R2
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R2
	adox	\T1, \R3
	adcq	$0, \R3

	// [R2:R4] += a5 x [a6:a7]
	movq	40+\A, %rdx
	xorq	\R4, \R4
	mulx	48+\A, \T0, \T1
	adcx	\T0, \R2
	adox	\T1, \R3
	mulx	56+\A, \T0, \T1
	adcx	\T0, \R3
	adox	\T1, \R4
	adcq	$0, \R4

	// [R4:R5] += a6 x a7
	movq	48+\A, %rdx
	mulx	56+\A, \T0, \R5
	addq	\T0, \R4
	adcq	$0, \R5

	// c <- 2 x [words 1 to 14] + [a0^2:a7^2]
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
	adcx	\R6, \R6
	adox	\T0, \R6
	movq	\R6, 48+\C
	adcx	\R7, \R7
	adox	\T1, \R7
	movq	\R7, 56+\C
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R8, \R8
	adox	\T0, \R8
	movq	\R8, 64+\C
	adcx	\R0, \R0
	adox	\T1, \R0
	movq	\R0, 72+\C
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R1, \R1
	adox	\T0, \R1
	movq	\R1, 80+\C
	adcx	\R2, \R2
	adox	\T1, \R2
	movq	\R2, 88+\C
	movq	48+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R3, \R3
	adox	\T0, \R3
	movq	\R3, 96+\C
	adcx	\R4, \R4
	adox	\T1, \R4
	movq	\R4, 104+\C
	movq	56+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\R5, \R5
	adox	\T0, \R5
	movq	\R5, 112+\C
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 120+\C
.endm

// c <- a^2 (RDC = 0) or a^2/2^512 mod p (RDC = 1), for a = 0+A. RDC = 0
// writes 0+C and needs 48 bytes of scratch at S; RDC = 1 writes 0(%rdi),
// which may alias a, and needs 128 bytes at S. T0 and T1 must differ from
// %rcx, %rdx, %rsi and %rdi.
.macro FP_SQR_LOW A, C, S, R0, R1, R2, R3, R4, R5, R6, R7, R8, T0, T1, P, RDC
.if \RDC != 1
	SQRN	\A, \C, \S, \R0, \R1, \R2, \R3, \R4, \R5, \R6, \R7, \R8, \T0, \T1
.else
	// The low half reduces to at most p and the high half is below p.
	SQRN	\A, \S, \S, \R0, \R1, \R2, \R3, \R4, \R5, \R6, \R7, \R8, \T0, \T1
	FP_RDCN_LOW	\S, \R0, \R1, \R2, \R3, \R4, \R5, \R6, \R7, \R8, \T0, \T1, \P
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif
	
	// [r9:r14, r8] <- z += 2 x a01 x a1
	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, \P
.endif

	// [r10:r14, r8:r9] <- z += 2 x a02 x a1
	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r14, r8:r10] <- z += 2 x a03 x a1
	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r14, r8:r11] <- z += 2 x a04 x a1
	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z += 2 x a05 x a1
	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z += 2 x a06 x a1
	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z += 2 x a07 x a1
	xorq	\Z6, \Z6
	movq	56+\A, %rdx
	MULADD	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	MULADD	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z8, 64(%rdi)
	movq	\Z0, 72(%rdi)
	movq	\Z1, 80(%rdi)
	movq	\Z2, 88(%rdi)
	movq	\Z3, 96(%rdi)
	movq	\Z4, 104(%rdi)
	movq	\Z5, 112(%rdi)
	movq	\Z6, 120(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P, RDC
	movq	64+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, 64+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z8
	sbbq	$0, \Z0

	// [r9:r14, r8] <- z = a0 x b01 - a1 x b11 + z 
	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, \B
	movq	72+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, 64+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	// [r10:r14, r8:r9] <- z = a0 x b02 - a1 x b12 + z 
	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, \B
	movq	80+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, 64+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	// [r11:r14, r8:r10] <- z = a0 x b03 - a1 x b13 + z
	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	88+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, 64+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	// [r12:r14, r8:r11] <- z = a0 x b04 - a1 x b14 + z 
	movq	32+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	96+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 64+\B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	// [r13:r14, r8:r12] <- z = a0 x b05 - a1 x b15 + z 
	movq	40+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	104+\A, %rdx
	MULSUB	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 64+\B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z5, \Z5
	btq		$63, \Z4
	sbbq	$0, \Z5

	movq	48+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
	movq	112+\A, %rdx
	MULSUB	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 64+\B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	xorq	\Z6, \Z6
	btq		$63, \Z5
	sbbq	$0, \Z6

	movq	56+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
	movq	120+\A, %rdx
	MULSUB	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 64+\B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	MULADD	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	btq		$63, \Z6

	// Correction if result < 0
	push	%rdi
	push	\Z6
    movq 	$0, \Z7
    movq 	$0, \T0
    movq 	$0, \T1
    movq 	$0, \Z6
    movq	$0, %rdx
    movq	$0, %rsi
	movq	$0, %rcx
	movq	$0, %rdi
    cmovc	p0(%rip), \Z7
    cmovc	p1(%rip), \T0
    cmovc	p2(%rip), \T1
    cmovc	p3(%rip), \Z6
    cmovc	p4(%rip), %rdx
    cmovc	p5(%rip), %rsi
	cmovc	p6(%rip), %rcx
	cmovc	p7(%rip), %rdi
	addq	\Z7, \Z8
	adcq	\T0, \Z0
	adcq	\T1, \Z1
	adcq	\Z6, \Z2
	popq	\Z6
	adcq	%rdx, \Z3
	adcq	%rsi, \Z4
	adcq	%rcx, \Z5
	adcq	%rdi, \Z6
	popq	%rdi
.if \RDC != 1
	movq	\Z8, 64(%rdi)
	movq	\Z0, 72(%rdi)
	movq	\Z1, 80(%rdi)
	movq	\Z2, 88(%rdi)
	movq	\Z3, 96(%rdi)
	movq	\Z4, 104(%rdi)
	movq	\Z5, 112(%rdi)
	movq	\Z6, 120(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P, RDC
	movq	64+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif

	// [r9:r14, r8] <- z = a0 x b11 + a1 x b01 + z		
	xorq	\Z0, \Z0 
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, 64+\B
	movq	72+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \T0, \T1, \P
.endif

	// [r10:r14, r8:r9] <- z = a0 x b12 + a1 x b02 + z		
	xorq	\Z1, \Z1 
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, 64+\B
	movq	80+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r14, r8:r10] <- z = a0 x b13 + a1 x b03 + z		
	xorq	\Z2, \Z2 
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, 64+\B
	movq	88+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r14, r8:r11] <- z = a0 x b14 + a1 x b04 + z		
	xorq	\Z3, \Z3 
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 64+\B
	movq	96+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z = a0 x b15 + a1 x b05 + z
	xorq	\Z4, \Z4 
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 64+\B
	movq	104+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 64+\B
	movq	112+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	xorq	\Z6, \Z6
	movq	56+\A, %rdx
	MULADD	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 64+\B
	movq	120+\A, %rdx
	MULADD	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	MULADD	\Z7, \Z8, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z8, 64(%rdi)
	movq	\Z0, 72(%rdi)
	movq	\Z1, 80(%rdi)
	movq	\Z2, 88(%rdi)
	movq	\Z3, 96(%rdi)
	movq	\Z4, 104(%rdi)
	movq	\Z5, 112(%rdi)
	movq	\Z6, 120(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1
.endif
.endm

// c <- a x b in Fp2 with u^2 = -1, for b = 0+B based on %rsi and a = 0+A
// based on %rcx. RDC = 0: c0 at %rdi and c1 at the pointer in 8+S. RDC = 1:
// c0 at %rdi and c1 at 64(%rdi), reduced, where c may alias a or b. S is 12
// words of scratch.
.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P, RDC, S
	movq	%rsi, 0+\S
	movq	%rcx, 16+\S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P, 0
	movq	0+\S, %rsi
	movq	16+\S, %rcx
	movq	8+\S, %rdi
	MULM	\A, 64+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P, 0
.else
	// c1 goes to the scratch space, since c0 still reads a1 and b1.
	movq	%rdi, 8+\S
	leaq	24+\S, %rdi
	MULM	\A, 64+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P, 1
	movq	0+\S, %rsi
	movq	16+\S, %rcx
	movq	8+\S, %rdi
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P, 1
	movq	24+\S, \Z0
	movq	32+\S, \Z1
	movq	40+\S, \Z2
	movq	48+\S, \Z3
	movq	56+\S, \Z4
	movq	64+\S, \Z5
	movq	72+\S, \Z6
	movq	80+\S, \Z7
	movq	\Z0, 64(%rdi)
	movq	\Z1, 72(%rdi)
	movq	\Z2, 80(%rdi)
	movq	\Z3, 88(%rdi)
	movq	\Z4, 96(%rdi)
	movq	\Z5, 104(%rdi)
	movq	\Z6, 112(%rdi)
	movq	\Z7, 120(%rdi)
.endif
.endm

// c <- a^2 in Fp2 with u^2 = -1, for a = 0+A based on %rsi:
// c0 = (a0 + a1) x (a0 - a1 + p), c1 = 2 x a0 x a1. RDC = 0: c0 at %rdi and
// c1 at the pointer in 192+S. RDC = 1: c0 at %rdi and c1 at 64(%rdi),
// reduced, where c may alias a. S is 26 words of scratch.
.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P, RDC, S
	// [0+S] <- a0 + a1, [64+S] <- a0 - a1 + p, [128+S] <- 2 x a0
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	56+\A, \Z7
	movq	\Z0, \T0
	addq	64+\A, \T0
	movq	\T0, 0+\S
	movq	\Z1, \T0
	adcq	72+\A, \T0
	movq	\T0, 8+\S
	movq	\Z2, \T0
	adcq	80+\A, \T0
	movq	\T0, 16+\S
	movq	\Z3, \T0
	adcq	88+\A, \T0
	movq	\T0, 24+\S
	movq	\Z4, \T0
	adcq	96+\A, \T0
	movq	\T0, 32+\S
	movq	\Z5, \T0
	adcq	104+\A, \T0
	movq	\T0, 40+\S
	movq	\Z6, \T0
	adcq	112+\A, \T0
	movq	\T0, 48+\S
	movq	\Z7, \T0
	adcq	120+\A, \T0
	movq	\T0, 56+\S
	movq	\Z0, \T0
	addq	\T0, \T0
	movq	\T0, 128+\S
	movq	\Z1, \T0
	adcq	\T0, \T0
	movq	\T0, 136+\S
	movq	\Z2, \T0
	adcq	\T0, \T0
	movq	\T0, 144+\S
	movq	\Z3, \T0
	adcq	\T0, \T0
	movq	\T0, 152+\S
	movq	\Z4, \T0
	adcq	\T0, \T0
	movq	\T0, 160+\S
	movq	\Z5, \T0
	adcq	\T0, \T0
	movq	\T0, 168+\S
	movq	\Z6, \T0
	adcq	\T0, \T0
	movq	\T0, 176+\S
	movq	\Z7, \T0
	adcq	\T0, \T0
	movq	\T0, 184+\S
	subq	64+\A, \Z0
	sbbq	72+\A, \Z1
	sbbq	80+\A, \Z2
	sbbq	88+\A, \Z3
	sbbq	96+\A, \Z4
	sbbq	104+\A, \Z5
	sbbq	112+\A, \Z6
	sbbq	120+\A, \Z7
	addq	0+\P, \Z0
	adcq	8+\P, \Z1
	adcq	16+\P, \Z2
	adcq	24+\P, \Z3
	adcq	32+\P, \Z4
	adcq	40+\P, \Z5
	adcq	48+\P, \Z6
	adcq	56+\P, \Z7
	movq	\Z0, 64+\S
	movq	\Z1, 72+\S
	movq	\Z2, 80+\S
	movq	\Z3, 88+\S
	movq	\Z4, 96+\S
	movq	\Z5, 104+\S
	movq	\Z6, 112+\S
	movq	\Z7, 120+\S

	// c1 first: it is the last reader of a, and c0 only reads the scratch.
.if \RDC != 1
	movq	%rdi, 200+\S
	movq	192+\S, %rdi
.else
	addq	$64, %rdi
.endif
	MULM	128+\S, 64+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0
	FP_MUL_LOW	128+\S, 64+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P, \RDC
.if \RDC != 1
	movq	200+\S, %rdi
.else
	subq	$64, %rdi
.endif
	MULM	0+\S, 64+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0
	FP_MUL_LOW	0+\S, 64+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P, \RDC
.endm
