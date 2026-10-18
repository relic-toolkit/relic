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

#if FP_PRIME == 254
#define P0	0xA700000000000013
#define P1	0x6121000000000013
#define P2	0xBA344D8000000008
#define P3	0x2523648240000001
#define U0	0x08435E50D79435E5
#define BAR	0xDC94C9081275E672
#define BARS	61
#elif FP_PRIME == 255
#define P0	0xFFFFFFFFFFFFFFED
#define P1	0xFFFFFFFFFFFFFFFF
#define P2	0xFFFFFFFFFFFFFFFF
#define P3	0x7FFFFFFFFFFFFFFF
#define U0	0x86BCA1AF286BCA1B
#define BAR	0x8000000000000000
#define BARS	62
#else
#error "x64-asm-4l supports only FP_PRIME = 254 or 255."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

#if P3 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

#if P3 < 0x5555555555555555
#define FP2_SQR_RDC
#endif

#if defined(FP_QNRES) && RLC_ALLOC == RLC_AUTO
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

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5
	movq	0+\A, %rdx
	mulx	0+\B, \Z0, \Z1
	xorq	%rax, %rax
	mulx	8+\B, \Z3, \Z2
	adox	\Z3, \Z1
	mulx	16+\B, \Z4, \Z3
	adox	\Z4, \Z2
	mulx	24+\B, \Z5, \Z4
	adox	\Z5, \Z3
	adox	%rax, \Z4
.endm

.macro MULADD Z0, Z1, Z2, Z3, Z4, T0, T1, M
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
	adcx	%rax, \Z4
.endm

.macro MULSUB Z0, Z1, Z2, Z3, Z4, T0, T1, M
	mulx	8+\M, \T1, \T0
	subq	\T1, \Z1
	sbbq	\T0, \Z2
	mulx	24+\M, \T1, \T0
	sbbq	\T1, \Z3
	sbbq	\T0, \Z4
	mulx	0+\M, \T1, \T0
	subq	\T1, \Z0
	sbbq	\T0, \Z1
	mulx	16+\M, \T1, \T0
	sbbq	\T1, \Z2
	sbbq	\T0, \Z3
	sbbq	$0, \Z4
.endm

.macro FINALC V0, V1, V2, V3, C0, C1, C2, C3, D
	movq	\V0, \C0
	movq	\V1, \C1
	movq	\V2, \C2
	movq	\V3, \C3
	subq	p0(%rip), \C0
	sbbq	p1(%rip), \C1
	sbbq	p2(%rip), \C2
	sbbq	p3(%rip), \C3
	cmovc	\V0, \C0
	cmovc	\V1, \C1
	cmovc	\V2, \C2
	cmovc	\V3, \C3
	movq	\C0, 0+\D
	movq	\C1, 8+\D
	movq	\C2, 16+\D
	movq	\C3, 24+\D
.endm

.macro RDCSTEP Z0, Z1, Z2, Z3, T0, T1, P
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
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

.macro RDCN Z0, Z1, Z2, Z3, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z0, \Z1, \Z2, \T0, \T1, \P
.endm

.macro ADDH Z0, Z1, Z2, Z3, H0, H1, H2, H3
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
.endm

.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, T0, T1, P, C0, C1, C2, C3
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	RDCN	\Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, 32+\A, 40+\A, 48+\A, 56+\A
	FINALC	\Z0, \Z1, \Z2, \Z3, \C0, \C1, \C2, \C3, 0(%rdi)
.endm

.macro SQRN A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1
	movq	0+\A, %rdx
	mulx	8+\A, \Z1, \Z2
	mulx	16+\A, \T0, \Z3
	addq	\T0, \Z2
	mulx	24+\A, \T0, \Z4
	adcq	\T0, \Z3
	adcq	$0, \Z4

	movq	8+\A, %rdx
	xorq	\Z5, \Z5
	mulx	16+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	adcq	$0, \Z5

	movq	16+\A, %rdx
	mulx	24+\A, \T0, \Z6
	addq	\T0, \Z5
	adcq	$0, \Z6

	movq	0+\A, %rdx
	mulx	%rdx, \Z0, \T1
	xorq	\T0, \T0
	adcx	\Z1, \Z1
	adox	\T1, \Z1
	movq	8+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z2, \Z2
	adox	\T0, \Z2
	adcx	\Z3, \Z3
	adox	\T1, \Z3
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z4, \Z4
	adox	\T0, \Z4
	adcx	\Z5, \Z5
	adox	\T1, \Z5
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	$0, \Z7
	adcx	\Z6, \Z6
	adox	\T0, \Z6
	adcx	\Z7, \Z7
	adox	\T1, \Z7
.endm

.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC
.if \RDC != 1
	SQRN	\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1
	movq	\Z0, 0(%rdi)
	movq	\Z1, 8(%rdi)
	movq	\Z2, 16(%rdi)
	movq	\Z3, 24(%rdi)
	movq	\Z4, 32(%rdi)
	movq	\Z5, 40(%rdi)
	movq	\Z6, 48(%rdi)
	movq	\Z7, 56(%rdi)
.else
	MULM	\A, \A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5
	FP_MUL_LOW	\A, \A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \P, 1
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \P
.endif

	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z4, 32(%rdi)
	movq	\Z0, 40(%rdi)
	movq	\Z1, 48(%rdi)
	movq	\Z2, 56(%rdi)
.else
	FINALC	\Z4, \Z0, \Z1, \Z2, \Z3, \T0, \T1, %rax, 0(%rdi)
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC
	movq	32+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 32+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z4
	sbbq	$0, \Z0

	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \B
	movq	40+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, 32+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \B
	movq	48+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, 32+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	56+\A, %rdx
	MULSUB	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, 32+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	testq	\Z2, \Z2

	movq	$0, \T0
	cmovs	p0(%rip), \T0
	adcx	\T0, \Z4
	movq	$0, \T1
	cmovs	p1(%rip), \T1
	adcx	\T1, \Z0
	movq	$0, \T0
	cmovs	p2(%rip), \T0
	adcx	\T0, \Z1
	movq	$0, \T1
	cmovs	p3(%rip), \T1
	adcx	\T1, \Z2
.if \RDC != 1
	movq	\Z4, 32(%rdi)
	movq	\Z0, 40(%rdi)
	movq	\Z1, 48(%rdi)
	movq	\Z2, 56(%rdi)
.else
	FINALC	\Z4, \Z0, \Z1, \Z2, \Z3, \T0, \T1, %rax, 0(%rdi)
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC
	movq	32+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, 32+\B
	movq	40+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \P
.endif

	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, 32+\B
	movq	48+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, 32+\B
	movq	56+\A, %rdx
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z4, 32(%rdi)
	movq	\Z0, 40(%rdi)
	movq	\Z1, 48(%rdi)
	movq	\Z2, 56(%rdi)
.else
	FINALC	\Z4, \Z0, \Z1, \Z2, \Z3, \T0, \T1, %rax, 0(%rdi)
.endif
.endm

.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, 0
	movq	0+\S, %rdi
	MULM	\A, 32+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, 0
.else
	movq	%rdi, 0+\S
	leaq	8+\S, %rdi
	MULM	\A, 32+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, 1
	movq	0+\S, %rdi
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, 1
	movq	8+\S, \Z0
	movq	16+\S, \Z1
	movq	24+\S, \Z2
	movq	32+\S, \Z3
	movq	\Z0, 32(%rdi)
	movq	\Z1, 40(%rdi)
	movq	\Z2, 48(%rdi)
	movq	\Z3, 56(%rdi)
.endif
.endm

.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC, S
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	\Z0, \Z4
	addq	32+\A, \Z4
	movq	\Z4, 0+\S
	movq	\Z1, \Z4
	adcq	40+\A, \Z4
	movq	\Z4, 8+\S
	movq	\Z2, \Z4
	adcq	48+\A, \Z4
	movq	\Z4, 16+\S
	movq	\Z3, \Z4
	adcq	56+\A, \Z4
	movq	\Z4, 24+\S
	movq	\Z0, \Z4
	addq	\Z0, \Z4
	movq	\Z4, 64+\S
	movq	\Z1, \Z4
	adcq	\Z1, \Z4
	movq	\Z4, 72+\S
	movq	\Z2, \Z4
	adcq	\Z2, \Z4
	movq	\Z4, 80+\S
	movq	\Z3, \Z4
	adcq	\Z3, \Z4
	movq	\Z4, 88+\S
	subq	32+\A, \Z0
	sbbq	40+\A, \Z1
	sbbq	48+\A, \Z2
	sbbq	56+\A, \Z3
	addq	0+\P, \Z0
	adcq	8+\P, \Z1
	adcq	16+\P, \Z2
	adcq	24+\P, \Z3
	movq	\Z0, 32+\S
	movq	\Z1, 40+\S
	movq	\Z2, 48+\S
	movq	\Z3, 56+\S

.if \RDC != 1
	movq	%rdi, 104+\S
	movq	96+\S, %rdi
.else
	addq	$32, %rdi
.endif
	MULM	64+\S, 32+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP_MUL_LOW	64+\S, 32+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, \RDC
.if \RDC != 1
	movq	104+\S, %rdi
.else
	subq	$32, %rdi
.endif
	MULM	0+\S, 32+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP_MUL_LOW	0+\S, 32+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, \RDC
.endm
