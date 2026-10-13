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

/* Both 446-bit primes are selected by fp_param_set() through the towering. */
#if FP_PRIME == 446
#ifdef FP_QNRES
/* B12_446 */
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
#else
/* BN_446 */
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
#endif
#else
#error "x64-asm-7l only supports FP_PRIME == 446"
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
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

.macro MULR A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8
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
	adox	%rax, \Z7
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
	mulx   48+\M, \T1, \T0
	adcx   \T1, \Z6
	adox   \T0, \Z7
	adcx   %rax,\Z7
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

// Final correction
.macro FINALC Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1
	movq	\Z7, \Z6
	movq	\Z0, \T0
	movq	\Z1, \T1
	movq	\Z2, %rax
	movq	\Z3, %rdx
	movq	\Z4, %rsi
	movq	\Z5, %rcx
	subq	p0(%rip), \Z6
	sbbq	p1(%rip), \T0
	sbbq	p2(%rip), \T1
	sbbq	p3(%rip), %rax
	sbbq	p4(%rip), %rdx
	sbbq	p5(%rip), %rsi
	sbbq	p6(%rip), %rcx
	cmovc	\Z7, \Z6
	cmovc	\Z0, \T0
	cmovc	\Z1, \T1
	cmovc	\Z2, %rax
	cmovc	\Z3, %rdx
	cmovc	\Z4, %rsi
	cmovc	\Z5, %rcx
	movq	\Z6, 0(%rdi)
	movq	\T0, 8(%rdi)
	movq	\T1, 16(%rdi)
	movq	%rax, 24(%rdi)
	movq	%rdx, 32(%rdi)
	movq	%rsi, 40(%rdi)
	movq	%rcx, 48(%rdi)
.endm

.macro FP_MULM_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r15] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	// [r9:r15, r8] <- z += a1 x b
	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r15, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \P
.endif

	// [r10:r15, r8:r9] <- z += a2 x b
	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r15, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r15, r8:r10] <- z += a3 x b
	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r15, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r15, r8:r11] <- z += a4 x b
	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r15, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// [r13:r15, r8:r12] <- z += a5 x b
	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14:r15, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	// [r14:r15, r8:r13] <- z += a6 x b
	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r15, r8:r13] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
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
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC
	movq	56+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r15] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z7
	sbbq	$0, \Z0

	// [r9:r15, r8] <- z = a01 x b0 - a11 x b1 + z
	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \B
	movq	64+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r15, r8] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	// [r10:r15, r8:r9] <- z = a02 x b0 - a12 x b1 + z
	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \B
	movq	72+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r15, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	// [r11:r15, r8:r10] <- z = a03 x b0 - a13 x b1 + z
	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	80+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r15, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	// [r12:r15, r8:r11] <- z = a04 x b0 - a14 x b1 + z
	movq	32+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	88+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r15, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	// [r13:r15, r8:r12] <- z = a05 x b0 - a15 x b1 + z
	movq	40+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	96+\A, %rdx
	MULSUB	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14:r15, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z5, \Z5
	btq		$63, \Z4
	sbbq	$0, \Z5

	// [r14:r15, r8:r13] <- z = a06 x b0 - a16 x b1 + z
	movq	48+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
	movq	104+\A, %rdx
	MULSUB	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 56+\B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r15, r8:r13] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	btq		$63, \Z5

	// Correction if result < 0
	movq	$0, \Z6
	movq	$0, \T0
	movq	$0, \T1
	movq	$0, %rax
	movq	$0, %rdx
	movq	$0, %rsi
	movq	$0, %rcx
	cmovc	p0(%rip), \Z6
	cmovc	p1(%rip), \T0
	cmovc	p2(%rip), \T1
	cmovc	p3(%rip), %rax
	cmovc	p4(%rip), %rdx
	cmovc	p5(%rip), %rsi
	cmovc	p6(%rip), %rcx
	addq	\Z6, \Z7
	adcq	\T0, \Z0
	adcq	\T1, \Z1
	adcq	%rax, \Z2
	adcq	%rdx, \Z3
	adcq	%rsi, \Z4
	adcq	%rcx, \Z5
.if \RDC != 1
	movq	\Z7, 56(%rdi)
	movq	\Z0, 64(%rdi)
	movq	\Z1, 72(%rdi)
	movq	\Z2, 80(%rdi)
	movq	\Z3, 88(%rdi)
	movq	\Z4, 96(%rdi)
	movq	\Z5, 104(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC
	movq	56+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [r9:r15] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	// [r9:r15, r8] <- z = a01 x b1 + a11 x b0 + z
	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, 56+\B
	movq	64+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [r10:r15, r8] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \T0, \T1, \P
.endif

	// [r10:r15, r8:r9] <- z = a02 x b1 + a12 x b0 + z
	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, 56+\B
	movq	72+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [r11:r15, r8:r9] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \T0, \T1, \P
.endif

	// [r11:r15, r8:r10] <- z = a03 x b1 + a13 x b0 + z
	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, 56+\B
	movq	80+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [r12:r15, r8:r10] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// [r12:r15, r8:r11] <- z = a04 x b1 + a14 x b0 + z
	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 56+\B
	movq	88+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\Z4, 32(%rdi)
.else
	// [r13:r15, r8:r11] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// [r13:r15, r8:r12] <- z = a05 x b1 + a15 x b0 + z
	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 56+\B
	movq	96+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z5, 40(%rdi)
.else
	// [r14:r15, r8:r12] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	// [r14:r15, r8:r13] <- z = a06 x b1 + a16 x b0 + z
	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 56+\B
	movq	104+\A, %rdx
	MULADD	\Z6, \Z7, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\Z6, 48(%rdi)
.else
	// [r15, r8:r13] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
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
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1
.endif
.endm
