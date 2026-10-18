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

#if FP_PRIME == 569
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
#elif FP_PRIME == 575
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
#else
#error "x64-asm-9l supports only FP_PRIME = 569 or 575."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

#if P8 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

#if P8 < 0x5555555555555555
#define FP2_SQR_RDC
#endif

#if defined(FP_QNRES) && RLC_ALLOC == RLC_AUTO
#define FP2_ASM
#endif

#if defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif

#if defined(__APPLE__)
.section __TEXT,__const
#else
.section .rodata
#endif
.p2align 3
ones:	.quad	-1

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
	movq	$0, \T1
	adcx	\T1, \Z9
.endm

.macro MULADD1 Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, X, T, ZR, M
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
	adox	\ZR, \X
	adcx	\ZR, \X
.endm

.macro MULRDC1 Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T, ZR, P
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T
	mulx	0+\P, \T, \T
	adcx	ones(%rip), \Z0
	adox	\T, \Z1
	mulx	8+\P, \T, \Z0
	adcx	\T, \Z1
	adox	\Z0, \Z2
	mulx	16+\P, \T, \Z0
	adcx	\T, \Z2
	adox	\Z0, \Z3
	mulx	24+\P, \T, \Z0
	adcx	\T, \Z3
	adox	\Z0, \Z4
	mulx	32+\P, \T, \Z0
	adcx	\T, \Z4
	adox	\Z0, \Z5
	mulx	40+\P, \T, \Z0
	adcx	\T, \Z5
	adox	\Z0, \Z6
	mulx	48+\P, \T, \Z0
	adcx	\T, \Z6
	adox	\Z0, \Z7
	mulx	56+\P, \T, \Z0
	adcx	\T, \Z7
	adox	\Z0, \Z8
	mulx	64+\P, \T, \Z0
	adcx	\T, \Z8
	adox	\Z0, \Z9
	adcx	\ZR, \Z9
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
.endm

.macro FINALC V0, V1, V2, V3, V4, V5, V6, V7, V8, C0, C1, C2, C3, C4, D
	movq	\V0, 0+\D
	movq	\V1, 8+\D
	movq	\V2, 16+\D
	movq	\V3, 24+\D
	movq	\V4, \C0
	movq	\V5, \C1
	movq	\V6, \C2
	movq	\V7, \C3
	movq	\V8, \C4
	subq	p0(%rip), \V0
	sbbq	p1(%rip), \V1
	sbbq	p2(%rip), \V2
	sbbq	p3(%rip), \V3
	sbbq	p4(%rip), \C0
	sbbq	p5(%rip), \C1
	sbbq	p6(%rip), \C2
	sbbq	p7(%rip), \C3
	sbbq	p8(%rip), \C4
	cmovc	0+\D, \V0
	cmovc	8+\D, \V1
	cmovc	16+\D, \V2
	cmovc	24+\D, \V3
	cmovc	\V4, \C0
	cmovc	\V5, \C1
	cmovc	\V6, \C2
	cmovc	\V7, \C3
	cmovc	\V8, \C4
	movq	\V0, 0+\D
	movq	\V1, 8+\D
	movq	\V2, 16+\D
	movq	\V3, 24+\D
	movq	\C0, 32+\D
	movq	\C1, 40+\D
	movq	\C2, 48+\D
	movq	\C3, 56+\D
	movq	\C4, 64+\D
.endm

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
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

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

.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, T0, T1, P, C0, C1, C2, C3, C4
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
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \C0, \C1, \C2, \C3, \C4, 0(%rdi)
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
	mulx	56+\A, \T0, \Z7
	adcq	\T0, \Z6
	mulx	64+\A, \T0, \Z8
	adcq	\T0, \Z7
	adcq	$0, \Z8
	movq	\Z0, 8+\O
	movq	\Z1, 16+\O

	movq	8+\A, %rdx
	xorq	\Z9, \Z9
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
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	adcq	$0, \Z9
	movq	\Z2, 24+\O
	movq	\Z3, 32+\O

	movq	16+\A, %rdx
	xorq	\Z0, \Z0
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
	adox	\T1, \Z0
	adcq	$0, \Z0
	movq	\Z4, 40+\O
	movq	\Z5, 48+\O

	movq	24+\A, %rdx
	xorq	\Z1, \Z1
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
	adox	\T1, \Z0
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	adcq	$0, \Z1

	movq	32+\A, %rdx
	xorq	\Z2, \Z2
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	adcq	$0, \Z2

	movq	40+\A, %rdx
	xorq	\Z3, \Z3
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

	movq	48+\A, %rdx
	xorq	\Z4, \Z4
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	adcq	$0, \Z4

	movq	56+\A, %rdx
	mulx	64+\A, \T0, \Z5
	addq	\T0, \Z4
	adcq	$0, \Z5

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
	movq	24+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 24+\O
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	32+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 32+\O
	movq	40+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 40+\O
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	48+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 48+\O
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
	adcx	\Z2, \Z2
	adox	\T1, \Z2
	movq	\Z2, 104+\O
	movq	56+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z3, \Z3
	adox	\T0, \Z3
	movq	\Z3, 112+\O
	adcx	\Z4, \Z4
	adox	\T1, \Z4
	movq	\Z4, 120+\O
	movq	64+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z5, \Z5
	adox	\T0, \Z5
	movq	\Z5, 128+\O
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 136+\O
.endm

.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
.if \RDC != 1
	SQRN	\A, 0(%rdi), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.else
	SQRN	\A, \S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
	FP_RDCN_LOW	\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \P, \Z9, \T0, %rdx, %rsi, \T1
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
	xorq	\T1, \T1
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	MULRDC1	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	8+\A, %rdx
	MULADD1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	MULRDC1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	16+\A, %rdx
	MULADD1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	MULRDC1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	24+\A, %rdx
	MULADD1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	MULRDC1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	32+\A, %rdx
	MULADD1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	MULRDC1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	40+\A, %rdx
	MULADD1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	MULRDC1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	48+\A, %rdx
	MULADD1	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	MULRDC1	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	56+\A, %rdx
	MULADD1	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	MULRDC1	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	64+\A, %rdx
	MULADD1	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\Z8, 64(%rdi)
.else
	MULRDC1	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
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
	FINALC	\Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, %rdx, %rcx, 0(%rdi)
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
	movq	72+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z9
	sbbq	$0, \Z0

	movq	8+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \B
	movq	80+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	movq	16+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \B
	movq	88+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	movq	24+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	96+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	movq	32+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	104+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	movq	40+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	112+\A, %rdx
	MULSUB	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z5, \Z5
	btq		$63, \Z4
	sbbq	$0, \Z5

	movq	48+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
	movq	120+\A, %rdx
	MULSUB	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	xorq	\Z6, \Z6
	btq		$63, \Z5
	sbbq	$0, \Z6

	movq	56+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
	movq	128+\A, %rdx
	MULSUB	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	xorq	\Z7, \Z7
	btq		$63, \Z6
	sbbq	$0, \Z7

	movq	64+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
	movq	136+\A, %rdx
	MULSUB	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 72+\B
.if \RDC != 1
	movq	\Z8, 64(%rdi)
.else
	xorq	\T1, \T1
	MULRDC1	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif
	testq	\Z7, \Z7

	movq	$0, \T0
	cmovs	p0(%rip), \T0
	adcx	\T0, \Z9
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
	movq	$0, \T1
	cmovs	p7(%rip), \T1
	adcx	\T1, \Z6
	movq	$0, \T0
	cmovs	p8(%rip), \T0
	adcx	\T0, \Z7
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
	FINALC	\Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, %rdx, %rcx, 0(%rdi)
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
	movq	72+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	MULRDC1	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	8+\A, %rdx
	MULADD1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, 72+\B
	movq	80+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	MULRDC1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	16+\A, %rdx
	MULADD1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, 72+\B
	movq	88+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	MULRDC1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	24+\A, %rdx
	MULADD1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, 72+\B
	movq	96+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	MULRDC1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	32+\A, %rdx
	MULADD1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 72+\B
	movq	104+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	MULRDC1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	40+\A, %rdx
	MULADD1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 72+\B
	movq	112+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	MULRDC1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	48+\A, %rdx
	MULADD1	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 72+\B
	movq	120+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	MULRDC1	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	56+\A, %rdx
	MULADD1	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 72+\B
	movq	128+\A, %rdx
	MULADD	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\Z7, 56(%rdi)
.else
	MULRDC1	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	64+\A, %rdx
	MULADD1	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 72+\B
	movq	136+\A, %rdx
	MULADD	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\Z8, 64(%rdi)
.else
	MULRDC1	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
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
	FINALC	\Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, %rdx, %rcx, 0(%rdi)
.endif
.endm

.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 0
	movq	0+\S, %rdi
	MULM	\A, 72+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 0
.else
	movq	%rcx, 8+\S
	movq	%rdi, 0+\S
	leaq	16+\S, %rdi
	MULM	\A, 72+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, 1
	movq	8+\S, %rcx
	movq	0+\S, %rdi
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

.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
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
	addq	\Z0, \Z9
	movq	\Z9, 144+\S
	movq	\Z1, \Z9
	adcq	\Z1, \Z9
	movq	\Z9, 152+\S
	movq	\Z2, \Z9
	adcq	\Z2, \Z9
	movq	\Z9, 160+\S
	movq	\Z3, \Z9
	adcq	\Z3, \Z9
	movq	\Z9, 168+\S
	movq	\Z4, \Z9
	adcq	\Z4, \Z9
	movq	\Z9, 176+\S
	movq	\Z5, \Z9
	adcq	\Z5, \Z9
	movq	\Z9, 184+\S
	movq	\Z6, \Z9
	adcq	\Z6, \Z9
	movq	\Z9, 192+\S
	movq	\Z7, \Z9
	adcq	\Z7, \Z9
	movq	\Z9, 200+\S
	movq	\Z8, \Z9
	adcq	\Z8, \Z9
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
