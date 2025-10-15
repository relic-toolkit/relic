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

.macro MULN i, j, k, C, R0, R1, R2, A, B
	.if \j > \k
		movq	8*\i(\A), %rax
		mulq	8*\j(\B)
		addq	%rax    , \R0
		adcq	%rdx    , \R1
		adcq	$0      , \R2
		MULN	"(\i + 1)", "(\j - 1)", \k, \C, \R0, \R1, \R2, \A, \B
	.else
		movq	8*\i(\A), %rax
		mulq	8*\j(\B)
		addq	%rax    , \R0
		movq	\R0     , 8*(\i+\j)(\C)
		adcq	%rdx    , \R1
		adcq	$0      , \R2
	.endif
.endm

.macro FP_MULN_LOW C, R0, R1, R2, A, B
	movq 	0(\A),%rax
	mulq 	0(\B)
	movq 	%rax ,0(\C)
	movq 	%rdx ,\R0

	xorq 	\R1,\R1
	xorq 	\R2,\R2
	MULN 	0, 1, 0, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	0, 2, 0, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	0, 3, 0, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	0, 4, 0, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	0, 5, 0, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	0, 6, 0, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	0, 7, 0, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	0, 8, 0, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	1, 8, 1, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	2, 8, 2, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	3, 8, 3, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	4, 8, 4, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	5, 8, 5, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	6, 8, 6, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	7, 8, 7, \C, \R2, \R0, \R1, \A, \B

	movq	64(\A),%rax
	mulq	64(\B)
	addq	%rax  ,\R0
	movq	\R0   ,128(\C)
	adcq	%rdx  ,\R1
	movq	\R1   ,136(\C)
.endm

.macro _RDCN0 i, j, k, R0, R1, R2 A, P
	movq	8*\i(\A), %rax
	mulq	8*\j(\P)
	addq	%rax, \R0
	adcq	%rdx, \R1
	adcq	$0, \R2
	.if \j > 1
		_RDCN0 "(\i + 1)", "(\j - 1)", \k, \R0, \R1, \R2, \A, \P
	.else
		addq	8*\k(\A), \R0
		adcq	$0, \R1
		adcq	$0, \R2
		movq	\R0, %rax
		mulq	%rcx
		movq	%rax, 8*\k(\A)
		mulq	0(\P)
		addq	%rax , \R0
		adcq	%rdx , \R1
		adcq	$0   , \R2
		xorq	\R0, \R0
	.endif
.endm

.macro RDCN0 i, j, R0, R1, R2, A, P
	_RDCN0	\i, \j, \j, \R0, \R1, \R2, \A, \P
.endm

.macro _RDCN1 i, j, k, l, R0, R1, R2 A, P
	movq	8*\i(\A), %rax
	mulq	8*\j(\P)
	addq	%rax, \R0
	adcq	%rdx, \R1
	adcq	$0, \R2
	.if \j > \l
		_RDCN1 "(\i + 1)", "(\j - 1)", \k, \l, \R0, \R1, \R2, \A, \P
	.else
		addq	8*\k(\A), \R0
		adcq	$0, \R1
		adcq	$0, \R2
		movq	\R0, 8*\k(\A)
		xorq	\R0, \R0
	.endif
.endm

.macro RDCN1 i, j, R0, R1, R2, A, P
	_RDCN1	\i, \j, "(\i + \j)", \i, \R0, \R1, \R2, \A, \P
.endm

// r8, r9, r10, r11, r12, r13, r14, r15, rbp, rbx, rsp, //rsi, rdi, //rax, rcx, rdx
.macro FP_RDCN_LOW C, R0, R1, R2, A, P
	xorq	\R1, \R1
	movq	$U0, %rcx

	movq	0(\A), \R0
	movq	\R0  , %rax
	mulq	%rcx
	movq	%rax , 0(\A)
	mulq	0(\P)
	addq	%rax , \R0
	adcq	%rdx , \R1
	xorq    \R2  , \R2
	xorq    \R0  , \R0

	RDCN0	0, 1, \R1, \R2, \R0, \A, \P
	RDCN0	0, 2, \R2, \R0, \R1, \A, \P
	RDCN0	0, 3, \R0, \R1, \R2, \A, \P
	RDCN0	0, 4, \R1, \R2, \R0, \A, \P
	RDCN0	0, 5, \R2, \R0, \R1, \A, \P
	RDCN0	0, 6, \R0, \R1, \R2, \A, \P
	RDCN0	0, 7, \R1, \R2, \R0, \A, \P
	RDCN0	0, 8, \R2, \R0, \R1, \A, \P
	RDCN1	1, 8, \R0, \R1, \R2, \A, \P
	RDCN1	2, 8, \R1, \R2, \R0, \A, \P
	RDCN1	3, 8, \R2, \R0, \R1, \A, \P
	RDCN1	4, 8, \R0, \R1, \R2, \A, \P
	RDCN1	5, 8, \R1, \R2, \R0, \A, \P
	RDCN1	6, 8, \R2, \R0, \R1, \A, \P
	RDCN1	7, 8, \R0, \R1, \R2, \A, \P
	RDCN1	8, 8, \R1, \R2, \R0, \A, \P
	addq	136(\A), \R2
	movq	\R2, 136(\A)

	movq	72(\A), %r11
	movq	80(\A), %r12
	movq	88(\A), %r13
	movq	96(\A), %r14
	movq	104(\A), %r15
	movq	112(\A), %rcx
	movq	120(\A), %rbp
	movq	128(\A), %rdx
	movq	136(\A), %r8

	subq	p0(%rip), %r11
	sbbq	p1(%rip), %r12
	sbbq	p2(%rip), %r13
	sbbq	p3(%rip), %r14
	sbbq	p4(%rip), %r15
	sbbq	p5(%rip), %rcx
	sbbq	p6(%rip), %rbp
	sbbq	p7(%rip), %rdx
	sbbq	p8(%rip), %r8

	cmovc	72(\A), %r11
	cmovc	80(\A), %r12
	cmovc	88(\A), %r13
	cmovc	96(\A), %r14
	cmovc	104(\A), %r15
	cmovc	112(\A), %rcx
	cmovc	120(\A), %rbp
	cmovc	128(\A), %rdx
	cmovc	136(\A), %r8
	movq	%r11,0(\C)
	movq	%r12,8(\C)
	movq	%r13,16(\C)
	movq	%r14,24(\C)
	movq	%r15,32(\C)
	movq	%rcx,40(\C)
	movq	%rbp,48(\C)
	movq	%rdx,56(\C)
	movq	%r8, 64(\C)
.endm
