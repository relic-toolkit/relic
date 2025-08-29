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

#if FP_PRIME == 315
#define P0	0x6FE802FF40300001
#define P1	0x421EE5DA52BDE502
#define P2	0xDEC1D01AA27A1AE0
#define P3	0xD3F7498BE97C5EAF
#define P4	0x04C23A02B586D650
#define U0	0x702FF9FF402FFFFF
#elif FP_PRIME == 317
#define P0	0x8D512E565DAB2AAB
#define P1	0xD6F339E43424BF7E
#define P2	0x169A61E684C73446
#define P3	0xF28FC5A0B7F9D039
#define P4	0x1058CA226F60892C
#define U0	0x55B5E0028B047FFD
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

.macro MULR A, Z0, Z1, Z2, Z3, Z4, Z5, Z6
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
	adox	%rax, \Z5
.endm

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6
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
	adox	%rax, \Z5
.endm

.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, M
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
	adcx   %rax,\Z5
.endm

.macro MULSUB Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, M
	mulx	8+\M, \T1, \T0
	subq	\T1, \Z1
	sbbq	\T0, \Z2
	mulx	24+\M, \T1, \T0
	sbbq	\T1, \Z3
	sbbq	\T0, \Z4
	sbbq	%rax, \Z5
	mulx	0+\M, \T1, \T0
	subq	\T1, \Z0
	sbbq	\T0, \Z1
	mulx	16+\M, \T1, \T0
	sbbq	\T1, \Z2
	sbbq	\T0, \Z3
	mulx	32+\M, \T1, \T0
	sbbq	\T1, \Z4
	sbbq	\T0, \Z5
	sbbq	%rax, \T0
.endm

.macro _MULSUB Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, M
	mulx	0+\M, \T1, \T0
	subq	\T1, \Z0
	sbbq	\T0, \Z1
	mulx	8+\M, \T1, \T0
	sbbq	\T1, \Z1
	sbbq	\T0, \Z2
	mulx	16+\M, \T1, \T0
	sbbq	\T1, \Z2
	sbbq	\T0, \Z3
	mulx	24+\M, \T1, \T0
	sbbq	\T1, \Z3
	sbbq	\T0, \Z4
	mulx	32+\M, \T1, \T0
	sbbq	\T1, \Z4
	sbbq	\T0, \Z5
	sbbq	%rax, \Z5
.endm

// Final correction
.macro FINALC Z0, Z1, Z2, Z3, Z4, Z5, T0, T1
	movq	\Z5, \Z4
	movq	\Z0, \T0
	movq	\Z1, \T1
	movq	\Z2, %rcx
	movq	\Z3, %rdx
	subq	p0(%rip), \Z4
	sbbq	p1(%rip), \T0
	sbbq	p2(%rip), \T1
	sbbq	p3(%rip), %rcx
	sbbq	p4(%rip), %rdx
	cmovc	\Z5, \Z4
	cmovc	\Z0, \T0
	cmovc	\Z1, \T1
	cmovc	\Z2, %rcx
	cmovc	\Z3, %rdx
	movq	\Z4, 0(%rdi)
	movq	\T0, 8(%rdi)
	movq	\T1, 16(%rdi)
	movq	%rcx, 24(%rdi)
	movq	%rdx, 32(%rdi)
.endm

.macro FP_MULM_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, %rcx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	
	// [r9:r14, r8] <- z += 2 x a01 x a1
	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, %rcx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, \P
.endif

	// [r10:r14, r8:r9] <- z += 2 x a02 x a1
	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, %rcx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r14, r8:r10] <- z += 2 x a03 x a1
	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, %rcx
	MULADD	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r14, r8:r11] <- z += 2 x a04 x a1
	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, %rcx
	MULADD	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z5, 40(%rdi)
	movq	\Z0, 48(%rdi)
	movq	\Z1, 56(%rdi)
	movq	\Z2, 64(%rdi)
	movq	\Z3, 72(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P, RDC
	movq	40+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 40+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, %rcx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z5
	sbbq	$0, \Z0

	// [r9:r14, r8] <- z = a0 x b01 - a1 x b11 + z 
	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, \B
	movq	48+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, 40+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, %rcx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	// [r10:r14, r8:r9] <- z = a0 x b02 - a1 x b12 + z 
	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, \B
	movq	56+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, 40+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, %rcx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	// [r11:r14, r8:r10] <- z = a0 x b03 - a1 x b13 + z
	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	64+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, 40+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, %rcx
	MULADD	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	// [r12:r14, r8:r11] <- z = a0 x b04 - a1 x b14 + z 
	movq	32+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	72+\A, %rdx
	MULSUB	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 40+\B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, %rcx
	MULADD	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	%rax, %rax
	btq		$63, \Z3
	sbbq	$0, %rax

	// Correction if result < 0
	movq	p0(%rip), \Z4
	movq	p1(%rip), \T0
	movq	p2(%rip), \T1
	movq	p3(%rip), %rcx
	movq	p4(%rip), %rdx
	andq	%rax, \Z4
	andq	%rax, \T0
	andq	%rax, \T1
	andq	%rax, %rcx
	andq	%rax, %rdx
	addq	\Z4, \Z5
	adcq	\T0, \Z0
	adcq	\T1, \Z1
	adcq	%rcx, \Z2
	adcq	%rdx, \Z3
.if \RDC != 1
	movq	\Z5, 40(%rdi)
	movq	\Z0, 48(%rdi)
	movq	\Z1, 56(%rdi)
	movq	\Z2, 64(%rdi)
	movq	\Z3, 72(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P, RDC
	movq	40+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r14] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, %rcx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	// [r9:r14, r8] <- z = a0 x b11 + a1 x b01 + z		
	xorq	\Z0, \Z0 
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, 40+\B
	movq	48+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r14, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, %rcx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, \P
.endif

	// [r10:r14, r8:r9] <- z = a0 x b12 + a1 x b02 + z		
	xorq	\Z1, \Z1 
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, 40+\B
	movq	56+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r14, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, %rcx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r14, r8:r10] <- z = a0 x b13 + a1 x b03 + z		
	xorq	\Z2, \Z2 
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, 40+\B
	movq	64+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r14, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, %rcx
	MULADD	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r14, r8:r11] <- z = a0 x b14 + a1 x b04 + z		
	xorq	\Z3, \Z3 
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 40+\B
	movq	72+\A, %rdx
	MULADD	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r14, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, %rcx
	MULADD	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z5, 40(%rdi)
	movq	\Z0, 48(%rdi)
	movq	\Z1, 56(%rdi)
	movq	\Z2, 64(%rdi)
	movq	\Z3, 72(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1
.endif
.endm