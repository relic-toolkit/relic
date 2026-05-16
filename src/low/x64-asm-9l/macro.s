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
 * @version $Id: relic_fp_add_low.c 88 2009-09-06 21:27:19Z dfaranha $
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
#endif

#if defined(__APPLE__)
#define cdecl(S) _PREFIX(,S)
#else
#define cdecl(S) S
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

.macro MULR A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10
	movq	0+\A, %rdx
	mulx	\Z0, \Z0, \Z1
	xorq	%rax, %rax
	mulx	\Z2, \Z3, \Z2
	adox	\Z3, \Z1
	mulx	\Z4, \Z4, \Z3
	adox	\Z4, \Z2
	mulx	\Z5, \Z5, \Z4
	adox	\Z5, \Z3
	mulx	\Z6, \Z6, \Z5
	adox	\Z6, \Z4
	mulx	\Z7, \Z7, \Z6
	adox	\Z7, \Z5
	mulx	\Z8, \Z8, \Z7
	adox	\Z8, \Z6
	mulx	\Z9, \Z9, \Z8
	adox	\Z9, \Z7
	mulx	\Z10, \Z10, \Z9
	adox	\Z10, \Z8
	adox	%rax, \Z9
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

.macro FP_MULM_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
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