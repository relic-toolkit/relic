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
#define P5	0x24C
#define U0	0x9876AE34F480DCDB
#elif FP_PRIME == 377
#define P0	0x8508C00000000001
#define P1	0x170B5D4430000000
#define P2	0x1EF3622FBA094800
#define P3	0x1A22D9F300F5138F
#define P4	0xC63B05C06CA1493B
#define P5	0X01AE3A4617C510EA
#define U0	0x8508BFFFFFFFFFFF
#elif FP_PRIME == 354
#define P0	0x470948C8C6AAAB1D
#define P1	0x2E5DA80FED8491B9
#define P2	0x8E6E049BE3926C48
#define P3	0xA1928ADE1A404A33
#define P4	0xEA98F0A5315F4B6B
#define P5	0x1428C74
#define U0	0xE03977E479F290CB
#elif FP_PRIME == 381
#define P0	0xB9FEFFFFFFFFAAAB
#define P1	0x1EABFFFEB153FFFF
#define P2	0x6730D2A0F6B0F624
#define P3	0x64774B84F38512BF
#define P4	0x4B1BA7B6434BACD7
#define P5	0x1A0111EA397FE69A
#define U0	0x89F3FFFCFFFCFFFD
#elif FP_PRIME == 382
#define P0	0x004E000000000013
#define P1	0x09480097801382BE
#define P2	0xA6E58DBE43002A06
#define P3	0x6F82CEFBE47879BB
#define P4	0x2D996CC179C6D166
#define P5	0x24009015183F9489
#define U0	0xDF615E50D79435E5
#elif FP_PRIME == 383
#define P0	0xDA371D6485AAB0AB
#define P1	0x7A8C3F298A64852B
#define P2	0xAC31B801696124F4
#define P3	0xA0AD462CF365A511
#define P4	0xA06DADC41FEA9284
#define P5	0x5565569564AB6EB5
#define U0	0x69BC0571073435FD
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

.macro MULR A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7
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
	adox	%rax, \Z6
.endm

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7
	movq	0+\A, %rdx
	xorq	%rax, %rax
	mulx	0+\B, \Z0, \Z1
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
	mulx   0+\M, \T1, \T0
	adox   \T1, \Z0
	adox   \T0, \Z1
	mulx   8+\M, \T1, \T0
	adcx   \T1, \Z1
	adox   \T0, \Z2
	mulx   16+\M, \T1, \T0
	adcx   \T1, \Z2
	adox   \T0, \Z3
	mulx   24+\M, \T1, \T0
	adcx   \T1, \Z3
	adox   \T0, \Z4
	mulx   32+\M, \T1, \T0
	adcx   \T1, \Z4
	adox   \T0, \Z5
	mulx   40+\M, \T1, \T0
	adcx   \T1, \Z5
	adox   \T0, \Z6
	adcx   %rax,\Z6
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
	sbbq	%rax, \Z6
.endm

// Final correction
.macro FINALC Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1
	movq	\Z6, \Z5
	movq	\Z0, \T0
	movq	\Z1, \T1
	movq	\Z2, %rax
	movq	\Z3, %rdx
	movq	\Z4, %rsi
	subq	p0(%rip), \Z5
	sbbq	p1(%rip), \T0
	sbbq	p2(%rip), \T1
	sbbq	p3(%rip), %rax
	sbbq	p4(%rip), %rdx
	sbbq	p5(%rip), %rsi
	cmovc	\Z6, \Z5
	cmovc	\Z0, \T0
	cmovc	\Z1, \T1
	cmovc	\Z2, %rax
	cmovc	\Z3, %rdx
	cmovc	\Z4, %rsi
	movq	\Z5, 0(%rdi)
	movq	\T0, 8(%rdi)
	movq	\T1, 16(%rdi)
	movq	%rax, 24(%rdi)
	movq	%rdx, 32(%rdi)
	movq	%rsi, 40(%rdi)
.endm

.macro FP_MULM_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, %rbx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	
	// [r9:r14, r8] <- z += 2 x a01 x a1
	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, %rbx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \P
.endif

	// [r10:r14, r8:r9] <- z += 2 x a02 x a1
	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, %rbx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r14, r8:r10] <- z += 2 x a03 x a1
	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, %rbx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r14, r8:r11] <- z += 2 x a04 x a1
	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, %rbx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z += 2 x a05 x a1
	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, %rbx
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
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC
	movq	48+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, %rbx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z6
	sbbq	$0, \Z0

	// [r9:r14, r8] <- z = a0 x b01 - a1 x b11 + z 
	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \B
	movq	56+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, %rbx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	// [r10:r14, r8:r9] <- z = a0 x b02 - a1 x b12 + z 
	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \B
	movq	64+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, %rbx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	// [r11:r14, r8:r10] <- z = a0 x b03 - a1 x b13 + z
	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	72+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, %rbx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	// [r12:r14, r8:r11] <- z = a0 x b04 - a1 x b14 + z 
	movq	32+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	80+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, %rbx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	// [r13:r14, r8:r12] <- z = a0 x b05 - a1 x b15 + z 
	movq	40+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	88+\A, %rdx
	MULSUB	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 48+\B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, %rbx
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	btq		$63, \Z4

	// Correction if result < 0
    movq 	$0, \Z5
    movq 	$0, \T0
    movq 	$0, \T1
    movq 	$0, %rax
    movq	$0, %rdx
    movq	$0, %rsi
    cmovc	p0(%rip), \Z5
    cmovc	p1(%rip), \T0
    cmovc	p2(%rip), \T1
    cmovc	p3(%rip), %rax
    cmovc	p4(%rip), %rdx
    cmovc	p5(%rip), %rsi
	addq	\Z5, \Z6
	adcq	\T0, \Z0
	adcq	\T1, \Z1
	adcq	%rax, \Z2
	adcq	%rdx, \Z3
	adcq	%rsi, \Z4
.if \RDC != 1
	movq	\Z6, 48(%rdi)
	movq	\Z0, 56(%rdi)
	movq	\Z1, 64(%rdi)
	movq	\Z2, 72(%rdi)
	movq	\Z3, 80(%rdi)
	movq	\Z4, 88(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC
	movq	48+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, %rbx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	// [r9:r14, r8] <- z = a0 x b11 + a1 x b01 + z		
	xorq	\Z0, \Z0 
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, 48+\B
	movq	56+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, %rbx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \P
.endif

	// [r10:r14, r8:r9] <- z = a0 x b12 + a1 x b02 + z		
	xorq	\Z1, \Z1 
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, 48+\B
	movq	64+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, %rbx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r14, r8:r10] <- z = a0 x b13 + a1 x b03 + z		
	xorq	\Z2, \Z2 
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, 48+\B
	movq	72+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, %rbx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r14, r8:r11] <- z = a0 x b14 + a1 x b04 + z		
	xorq	\Z3, \Z3 
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 48+\B
	movq	80+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, %rbx
	MULADD	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// [r13:r14, r8:r12] <- z = a0 x b15 + a1 x b05 + z
	xorq	\Z4, \Z4 
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 48+\B
	movq	88+\A, %rdx
	MULADD	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, %rbx
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
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1
.endif
.endm