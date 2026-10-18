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

#if FP_PRIME == 330
#define P0	0x523E67A53D5C40AD
#define P1	0x27BBEC8F954D9613
#define P2	0xF12A1C4947A0784F
#define P3	0x5BF00BAF1EE31FEC
#define P4	0x0832E1406555615B
#define P5	0x000000000000024C
#define U0	0x9876AE34F480DCDB
#define BAR	0xDEE640A79148522C
#define BARS	9
#elif FP_PRIME == 354
#define P0	0x470948C8C6AAAB1D
#define P1	0x2E5DA80FED8491B9
#define P2	0x8E6E049BE3926C48
#define P3	0xA1928ADE1A404A33
#define P4	0xEA98F0A5315F4B6B
#define P5	0x0000000001428C74
#define U0	0xE03977E479F290CB
#define BAR	0xCB2E86F72F80D144
#define BARS	24
#elif FP_PRIME == 377
#define P0	0x8508C00000000001
#define P1	0x170B5D4430000000
#define P2	0x1EF3622FBA094800
#define P3	0x1A22D9F300F5138F
#define P4	0xC63B05C06CA1493B
#define P5	0x01AE3A4617C510EA
#define U0	0x8508BFFFFFFFFFFF
#define BAR	0x98542343310183A5
#define BARS	56
#elif FP_PRIME == 381 && defined(EC_SUPER)
#define P0	0x00000000FFFFFFFF
#define P1	0x0000000000800000
#define P2	0xAE328A41F46782B7
#define P3	0x08A88098F51FEBEF
#define P4	0xBD99C96E04729F8F
#define P5	0x10D3D10D00EE5D72
#define U0	0x0000000100000001
#define BAR	0xF369935F9A3B36B4
#define BARS	60
#elif FP_PRIME == 381
#define P0	0xB9FEFFFFFFFFAAAB
#define P1	0x1EABFFFEB153FFFF
#define P2	0x6730D2A0F6B0F624
#define P3	0x64774B84F38512BF
#define P4	0x4B1BA7B6434BACD7
#define P5	0x1A0111EA397FE69A
#define U0	0x89F3FFFCFFFCFFFD
#define BAR	0x9D835D2F3CC9E45C
#define BARS	60
#elif FP_PRIME == 382
#define P0	0x004E000000000013
#define P1	0x09480097801382BE
#define P2	0xA6E58DBE43002A06
#define P3	0x6F82CEFBE47879BB
#define P4	0x2D996CC179C6D166
#define P5	0x24009015183F9489
#define U0	0xDF615E50D79435E5
#define BAR	0xE38AAA3390990973
#define BARS	61
#elif FP_PRIME == 383
#define P0	0xDA371D6485AAB0AB
#define P1	0x7A8C3F298A64852B
#define P2	0xAC31B801696124F4
#define P3	0xA0AD462CF365A511
#define P4	0xA06DADC41FEA9284
#define P5	0x5565569564AB6EB5
#define U0	0x69BC0571073435FD
#define BAR	0xBFDC03EFA7869295
#define BARS	62
#else
#error "x64-asm-6l supports only FP_PRIME = 330, 354, 377, 381, 382 or 383."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

#if P5 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

#if P5 < 0x5555555555555555
#define FP2_SQR_RDC
#endif

#if (defined(FP_QNRES) || (FP_PRIME == 381 && defined(EC_SUPER))) && RLC_ALLOC == RLC_AUTO
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

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7
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
	adox	%rax, \Z6
.endm

.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, M
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
	adcx	%rax, \Z6
.endm

.macro MULSUB Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, M
	mulx	8+\M, \T1, \T0
	subq	\T1, \Z1
	sbbq	\T0, \Z2
	mulx	24+\M, \T1, \T0
	sbbq	\T1, \Z3
	sbbq	\T0, \Z4
	mulx	40+\M, \T1, \T0
	sbbq	\T1, \Z5
	sbbq	\T0, \Z6
	mulx	0+\M, \T1, \T0
	subq	\T1, \Z0
	sbbq	\T0, \Z1
	mulx	16+\M, \T1, \T0
	sbbq	\T1, \Z2
	sbbq	\T0, \Z3
	mulx	32+\M, \T1, \T0
	sbbq	\T1, \Z4
	sbbq	\T0, \Z5
	sbbq	$0, \Z6
.endm

.macro FINALC V0, V1, V2, V3, V4, V5, C0, C1, C2, C3, C4, C5, D
	movq	\V0, \C0
	movq	\V1, \C1
	movq	\V2, \C2
	movq	\V3, \C3
	movq	\V4, \C4
	movq	\V5, \C5
	subq	p0(%rip), \C0
	sbbq	p1(%rip), \C1
	sbbq	p2(%rip), \C2
	sbbq	p3(%rip), \C3
	sbbq	p4(%rip), \C4
	sbbq	p5(%rip), \C5
	cmovc	\V0, \C0
	cmovc	\V1, \C1
	cmovc	\V2, \C2
	cmovc	\V3, \C3
	cmovc	\V4, \C4
	cmovc	\V5, \C5
	movq	\C0, 0+\D
	movq	\C1, 8+\D
	movq	\C2, 16+\D
	movq	\C3, 24+\D
	movq	\C4, 32+\D
	movq	\C5, 40+\D
.endm

.macro RDCSTEP Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P
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
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z5, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endm

.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, H0, H1, H2, H3, H4, H5
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
	adcq	\H5, \Z5
.endm

.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P, C0, C1, C2, C3, C4, C5
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, 48+\A, 56+\A, 64+\A, 72+\A, 80+\A, 88+\A
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \C0, \C1, \C2, \C3, \C4, \C5, 0(%rdi)
.endm

.macro SQRN A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1
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
	adcq	$0, \Z6

	movq	8+\A, %rdx
	xorq	\Z7, \Z7
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
	adcq	$0, \Z7

	movq	16+\A, %rdx
	xorq	\Z8, \Z8
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	adcq	$0, \Z8

	movq	24+\A, %rdx
	xorq	\Z9, \Z9
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	adcq	$0, \Z9

	movq	32+\A, %rdx
	mulx	40+\A, \T0, \Z10
	addq	\T0, \Z9
	adcq	$0, \Z10

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
	adcx	\Z6, \Z6
	adox	\T0, \Z6
	adcx	\Z7, \Z7
	adox	\T1, \Z7
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z8, \Z8
	adox	\T0, \Z8
	adcx	\Z9, \Z9
	adox	\T1, \Z9
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	$0, \Z11
	adcx	\Z10, \Z10
	adox	\T0, \Z10
	adcx	\Z11, \Z11
	adox	\T1, \Z11
.endm

.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, P, RDC
.if \RDC != 1
	SQRN	\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1
	popq	%rdx
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
	movq	\Z11, 88(%rdx)
.else
	SQRN	\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11
	popq	%rdi
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T1, \Z6, \Z7, %rax, %rdx, %rsi, 0(%rdi)
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \P
.endif

	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z6, 48(%rdi)
	movq	\Z0, 56(%rdi)
	movq	\Z1, 64(%rdi)
	movq	\Z2, 72(%rdi)
	movq	\Z3, 80(%rdi)
	movq	\Z4, 88(%rdi)
.else
	FINALC	\Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, %rax, %rdx, %rsi, 0(%rdi)
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC
	movq	48+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z6
	sbbq	$0, \Z0

	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \B
	movq	56+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \B
	movq	64+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	72+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	movq	32+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	80+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	movq	40+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	88+\A, %rdx
	MULSUB	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	testq	\Z4, \Z4

	movq	$0, \T0
	cmovs	p0(%rip), \T0
	adcx	\T0, \Z6
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
.if \RDC != 1
	movq	\Z6, 48(%rdi)
	movq	\Z0, 56(%rdi)
	movq	\Z1, 64(%rdi)
	movq	\Z2, 72(%rdi)
	movq	\Z3, 80(%rdi)
	movq	\Z4, 88(%rdi)
.else
	FINALC	\Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, %rax, %rdx, %rsi, 0(%rdi)
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC
	movq	48+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, 48+\B
	movq	56+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \P
.endif

	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, 48+\B
	movq	64+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, 48+\B
	movq	72+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 48+\B
	movq	80+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 48+\B
	movq	88+\A, %rdx
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z6, 48(%rdi)
	movq	\Z0, 56(%rdi)
	movq	\Z1, 64(%rdi)
	movq	\Z2, 72(%rdi)
	movq	\Z3, 80(%rdi)
	movq	\Z4, 88(%rdi)
.else
	FINALC	\Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, %rax, %rdx, %rsi, 0(%rdi)
.endif
.endm

.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, 0
	movq	0+\S, %rdi
	MULM	\A, 48+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, 0
.else
	movq	%rsi, 8+\S
	movq	%rdi, 0+\S
	leaq	16+\S, %rdi
	MULM	\A, 48+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, 1
	movq	8+\S, %rsi
	movq	0+\S, %rdi
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, 1
	movq	16+\S, \Z0
	movq	24+\S, \Z1
	movq	32+\S, \Z2
	movq	40+\S, \Z3
	movq	48+\S, \Z4
	movq	56+\S, \Z5
	movq	\Z0, 48(%rdi)
	movq	\Z1, 56(%rdi)
	movq	\Z2, 64(%rdi)
	movq	\Z3, 72(%rdi)
	movq	\Z4, 80(%rdi)
	movq	\Z5, 88(%rdi)
.endif
.endm

.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC, S
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	\Z0, \Z6
	addq	48+\A, \Z6
	movq	\Z6, 0+\S
	movq	\Z1, \Z6
	adcq	56+\A, \Z6
	movq	\Z6, 8+\S
	movq	\Z2, \Z6
	adcq	64+\A, \Z6
	movq	\Z6, 16+\S
	movq	\Z3, \Z6
	adcq	72+\A, \Z6
	movq	\Z6, 24+\S
	movq	\Z4, \Z6
	adcq	80+\A, \Z6
	movq	\Z6, 32+\S
	movq	\Z5, \Z6
	adcq	88+\A, \Z6
	movq	\Z6, 40+\S
	movq	\Z0, \Z6
	addq	\Z0, \Z6
	movq	\Z6, 96+\S
	movq	\Z1, \Z6
	adcq	\Z1, \Z6
	movq	\Z6, 104+\S
	movq	\Z2, \Z6
	adcq	\Z2, \Z6
	movq	\Z6, 112+\S
	movq	\Z3, \Z6
	adcq	\Z3, \Z6
	movq	\Z6, 120+\S
	movq	\Z4, \Z6
	adcq	\Z4, \Z6
	movq	\Z6, 128+\S
	movq	\Z5, \Z6
	adcq	\Z5, \Z6
	movq	\Z6, 136+\S
	subq	48+\A, \Z0
	sbbq	56+\A, \Z1
	sbbq	64+\A, \Z2
	sbbq	72+\A, \Z3
	sbbq	80+\A, \Z4
	sbbq	88+\A, \Z5
	addq	0+\P, \Z0
	adcq	8+\P, \Z1
	adcq	16+\P, \Z2
	adcq	24+\P, \Z3
	adcq	32+\P, \Z4
	adcq	40+\P, \Z5
	movq	\Z0, 48+\S
	movq	\Z1, 56+\S
	movq	\Z2, 64+\S
	movq	\Z3, 72+\S
	movq	\Z4, 80+\S
	movq	\Z5, 88+\S

.if \RDC != 1
	movq	%rdi, 152+\S
	movq	144+\S, %rdi
.else
	addq	$48, %rdi
.endif
	MULM	96+\S, 48+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP_MUL_LOW	96+\S, 48+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, \RDC
.if \RDC != 1
	movq	152+\S, %rdi
.else
	subq	$48, %rdi
.endif
	MULM	0+\S, 48+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP_MUL_LOW	0+\S, 48+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, \RDC
.endm
