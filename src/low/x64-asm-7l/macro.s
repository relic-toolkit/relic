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
 * Implementation of low-level prime field multiplication.
 *
 * @version $Id: relic_fp_add_low.c 88 2009-09-06 21:27:19Z dfaranha $
 * @ingroup fp
 */

#if FP_PRIME == 446 && defined(FP_QNRES)
#define P0	0x311C0026AAB0AAAB
#define P1	0x56EE4528C573B5CC
#define P2	0x824E6DC3E23ACDEE
#define P3	0x0F75A64BBAC71602
#define P4	0x0095A4B78A02FE32
#define P5	0x200FC34965AAD640
#define P6	0x3CDEE0FB28C5E535
#define U0	0xCD63FD900035FFFD
#define BAR	0x86949D39F3509105
#define BARS	61
#define BARJ	6
#elif FP_PRIME == 446
#define P0	0x0000132000000067
#define P1	0x0057C00000015C00
#define P2	0x870000000B040000
#define P3	0x0000001800000000
#define P4	0x00000D800000021C
#define P5	0x002400000002D000
#define P6	0x2400000000000000
#define U0	0x6BD6C9022CBCE4A9
#define BAR	0xE38E38E38E38E38E
#define BARS	61
#define BARJ	6
#else
#error "x64-asm-7l supports only FP_PRIME = 446."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

#if P6 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

#if P6 < 0x5555555555555555
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

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8
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
	adox	%rax, \Z7
.endm

.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, M
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
	adcx	%rax, \Z7
.endm

.macro MULSUB Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, M
	mulx	8+\M, \T1, \T0
	subq	\T1, \Z1
	sbbq	\T0, \Z2
	mulx	24+\M, \T1, \T0
	sbbq	\T1, \Z3
	sbbq	\T0, \Z4
	mulx	40+\M, \T1, \T0
	sbbq	\T1, \Z5
	sbbq	\T0, \Z6
	sbbq	$0, \Z7
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
.endm

.macro FINALC V0, V1, V2, V3, V4, V5, V6, C0, C1, C2, C3, C4, C5, C6, D
	movq	\V0, \C0
	movq	\V1, \C1
	movq	\V2, \C2
	movq	\V3, \C3
	movq	\V4, \C4
	movq	\V5, \C5
	movq	\V6, \C6
	subq	p0(%rip), \C0
	sbbq	p1(%rip), \C1
	sbbq	p2(%rip), \C2
	sbbq	p3(%rip), \C3
	sbbq	p4(%rip), \C4
	sbbq	p5(%rip), \C5
	sbbq	p6(%rip), \C6
	cmovc	\V0, \C0
	cmovc	\V1, \C1
	cmovc	\V2, \C2
	cmovc	\V3, \C3
	cmovc	\V4, \C4
	cmovc	\V5, \C5
	cmovc	\V6, \C6
	movq	\C0, 0+\D
	movq	\C1, 8+\D
	movq	\C2, 16+\D
	movq	\C3, 24+\D
	movq	\C4, 32+\D
	movq	\C5, 40+\D
	movq	\C6, 48+\D
.endm

.macro RDCSTEP Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P
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
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	RDCSTEP	\Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endm

.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, Z6, H0, H1, H2, H3, H4, H5, H6
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
	adcq	\H5, \Z5
	adcq	\H6, \Z6
.endm

.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, C0, C1, C2, C3, C4, C5, C6
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, 56+\A, 64+\A, 72+\A, 80+\A, 88+\A, 96+\A, 104+\A
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \C0, \C1, \C2, \C3, \C4, \C5, \C6, 0(%rdi)
.endm

.macro SQRN A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1
	movq	0+\A, %rdx
	mulx	8+\A, \Z0, \Z1
	mulx	16+\A, \T0, \Z2
	addq	\T0, \Z1
	mulx	24+\A, \T0, \Z3
	adcq	\T0, \Z2
	mulx	32+\A, \T0, \Z4
	adcq	\T0, \Z3
	mulx	40+\A, \T0, \Z5
	adcq	\T0, \Z4
	mulx	48+\A, \T0, \Z6
	adcq	\T0, \Z5
	adcq	$0, \Z6
	movq	\Z0, 8+\O
	movq	\Z1, 16+\O

	movq	8+\A, %rdx
	xorq	\Z7, \Z7
	mulx	16+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	adcq	$0, \Z7

	movq	16+\A, %rdx
	xorq	\Z8, \Z8
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
	adcq	$0, \Z8

	movq	24+\A, %rdx
	xorq	\Z9, \Z9
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	adcq	$0, \Z9

	movq	32+\A, %rdx
	xorq	\Z0, \Z0
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	adcq	$0, \Z0

	movq	40+\A, %rdx
	mulx	48+\A, \T0, \Z1
	addq	\T0, \Z0
	adcq	$0, \Z1

	movq	0+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	\T0, 0+\O
	xorq	\T0, \T0
	movq	8+\O, \T0
	adcx	\T0, \T0
	adox	\T1, \T0
	movq	\T0, 8+\O
	movq	8+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	16+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 16+\O
	adcx	\Z2, \Z2
	adox	\T1, \Z2
	movq	\Z2, 24+\O
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z3, \Z3
	adox	\T0, \Z3
	movq	\Z3, 32+\O
	adcx	\Z4, \Z4
	adox	\T1, \Z4
	movq	\Z4, 40+\O
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z5, \Z5
	adox	\T0, \Z5
	movq	\Z5, 48+\O
	adcx	\Z6, \Z6
	adox	\T1, \Z6
	movq	\Z6, 56+\O
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z7, \Z7
	adox	\T0, \Z7
	movq	\Z7, 64+\O
	adcx	\Z8, \Z8
	adox	\T1, \Z8
	movq	\Z8, 72+\O
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z9, \Z9
	adox	\T0, \Z9
	movq	\Z9, 80+\O
	adcx	\Z0, \Z0
	adox	\T1, \Z0
	movq	\Z0, 88+\O
	movq	48+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z1, \Z1
	adox	\T0, \Z1
	movq	\Z1, 96+\O
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 104+\O
.endm

.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
.if \RDC != 1
	SQRN	\A, 0(%rdi), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.else
	SQRN	\A, \S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
	FP_RDCN_LOW	\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \P, \Z7, \Z8, %rdx, %rsi, \Z9, \T0, \T1
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \P
.endif

	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T1
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z7, 56(%rdi)
	movq	\Z0, 64(%rdi)
	movq	\Z1, 72(%rdi)
	movq	\Z2, 80(%rdi)
	movq	\Z3, 88(%rdi)
	movq	\Z4, 96(%rdi)
	movq	\Z5, 104(%rdi)
.else
	FINALC	\Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, %rax, %rdx, %rsi, %rcx, 0(%rdi)
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC
	movq	56+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z7
	sbbq	$0, \Z0

	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \B
	movq	64+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \B
	movq	72+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	80+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	movq	32+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	88+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	movq	40+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	96+\A, %rdx
	MULSUB	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z5, \Z5
	btq		$63, \Z4
	sbbq	$0, \Z5

	movq	48+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
	movq	104+\A, %rdx
	MULSUB	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T1
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	testq	\Z5, \Z5

	movq	$0, \T0
	cmovs	p0(%rip), \T0
	adcx	\T0, \Z7
	movq	$0, \T1
	cmovs	p1(%rip), \T1
	adcx	\T1, \Z0
	movq	$0, \T0
	cmovs	p2(%rip), \T0
	adcx	\T0, \Z1
	movq	$0, \T1
	cmovs	p3(%rip), \T1
	adcx	\T1, \Z2
	movq	$0, \T0
	cmovs	p4(%rip), \T0
	adcx	\T0, \Z3
	movq	$0, \T1
	cmovs	p5(%rip), \T1
	adcx	\T1, \Z4
	movq	$0, \T0
	cmovs	p6(%rip), \T0
	adcx	\T0, \Z5
.if \RDC != 1
	movq	\Z7, 56(%rdi)
	movq	\Z0, 64(%rdi)
	movq	\Z1, 72(%rdi)
	movq	\Z2, 80(%rdi)
	movq	\Z3, 88(%rdi)
	movq	\Z4, 96(%rdi)
	movq	\Z5, 104(%rdi)
.else
	FINALC	\Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, %rax, %rdx, %rsi, %rcx, 0(%rdi)
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC
	movq	56+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, 56+\B
	movq	64+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \P
.endif

	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, 56+\B
	movq	72+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, 56+\B
	movq	80+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 56+\B
	movq	88+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 56+\B
	movq	96+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 56+\B
	movq	104+\A, %rdx
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T1
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z7, 56(%rdi)
	movq	\Z0, 64(%rdi)
	movq	\Z1, 72(%rdi)
	movq	\Z2, 80(%rdi)
	movq	\Z3, 88(%rdi)
	movq	\Z4, 96(%rdi)
	movq	\Z5, 104(%rdi)
.else
	FINALC	\Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, %rax, %rdx, %rsi, %rcx, 0(%rdi)
.endif
.endm

.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, 0
	movq	0+\S, %rdi
	MULM	\A, 56+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, 0
.else
	movq	%rsi, 8+\S
	movq	%rcx, 16+\S
	movq	%rdi, 0+\S
	leaq	24+\S, %rdi
	MULM	\A, 56+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, 1
	movq	8+\S, %rsi
	movq	16+\S, %rcx
	movq	0+\S, %rdi
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, 1
	movq	24+\S, \Z0
	movq	32+\S, \Z1
	movq	40+\S, \Z2
	movq	48+\S, \Z3
	movq	56+\S, \Z4
	movq	64+\S, \Z5
	movq	72+\S, \Z6
	movq	\Z0, 56(%rdi)
	movq	\Z1, 64(%rdi)
	movq	\Z2, 72(%rdi)
	movq	\Z3, 80(%rdi)
	movq	\Z4, 88(%rdi)
	movq	\Z5, 96(%rdi)
	movq	\Z6, 104(%rdi)
.endif
.endm

.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC, S
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	\Z0, \Z7
	addq	56+\A, \Z7
	movq	\Z7, 0+\S
	movq	\Z1, \Z7
	adcq	64+\A, \Z7
	movq	\Z7, 8+\S
	movq	\Z2, \Z7
	adcq	72+\A, \Z7
	movq	\Z7, 16+\S
	movq	\Z3, \Z7
	adcq	80+\A, \Z7
	movq	\Z7, 24+\S
	movq	\Z4, \Z7
	adcq	88+\A, \Z7
	movq	\Z7, 32+\S
	movq	\Z5, \Z7
	adcq	96+\A, \Z7
	movq	\Z7, 40+\S
	movq	\Z6, \Z7
	adcq	104+\A, \Z7
	movq	\Z7, 48+\S
	movq	\Z0, \Z7
	addq	\Z0, \Z7
	movq	\Z7, 112+\S
	movq	\Z1, \Z7
	adcq	\Z1, \Z7
	movq	\Z7, 120+\S
	movq	\Z2, \Z7
	adcq	\Z2, \Z7
	movq	\Z7, 128+\S
	movq	\Z3, \Z7
	adcq	\Z3, \Z7
	movq	\Z7, 136+\S
	movq	\Z4, \Z7
	adcq	\Z4, \Z7
	movq	\Z7, 144+\S
	movq	\Z5, \Z7
	adcq	\Z5, \Z7
	movq	\Z7, 152+\S
	movq	\Z6, \Z7
	adcq	\Z6, \Z7
	movq	\Z7, 160+\S
	subq	56+\A, \Z0
	sbbq	64+\A, \Z1
	sbbq	72+\A, \Z2
	sbbq	80+\A, \Z3
	sbbq	88+\A, \Z4
	sbbq	96+\A, \Z5
	sbbq	104+\A, \Z6
	addq	0+\P, \Z0
	adcq	8+\P, \Z1
	adcq	16+\P, \Z2
	adcq	24+\P, \Z3
	adcq	32+\P, \Z4
	adcq	40+\P, \Z5
	adcq	48+\P, \Z6
	movq	\Z0, 56+\S
	movq	\Z1, 64+\S
	movq	\Z2, 72+\S
	movq	\Z3, 80+\S
	movq	\Z4, 88+\S
	movq	\Z5, 96+\S
	movq	\Z6, 104+\S

.if \RDC != 1
	movq	%rdi, 176+\S
	movq	168+\S, %rdi
.else
	addq	$56, %rdi
.endif
	MULM	112+\S, 56+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP_MUL_LOW	112+\S, 56+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, \RDC
.if \RDC != 1
	movq	176+\S, %rdi
.else
	subq	$56, %rdi
.endif
	MULM	0+\S, 56+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP_MUL_LOW	0+\S, 56+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, \RDC
.endm
