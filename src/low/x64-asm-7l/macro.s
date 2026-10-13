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

/*
 * FP2_MUL0_LOW with RDC = 1 keeps the real part as a signed value in (-p, 2p),
 * which only fits RLC_FP_DIGS digits when 2p < 2^447, that is, p < 2^446.
 */
#if P6 < 0x4000000000000000
#define FP2_MUL_RDC
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

// Montgomery step on a window with no word above it:
// [Z1:Z6, Z0] <- ([Z0:Z6] + (Z0 x u0 mod 2^64) x p)/2^64.
// The result is below 2^384 + p, so it fits the window and no carry leaves it.
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
	// Z0 is zero here, so this cannot overflow.
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

// [Z0:Z6] <- [Z0:Z6]/2^448 mod p, at most p, by seven Montgomery steps.
.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z5, \Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	RDCSTEP	\Z6, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endm

// [Z0:Z6] += [H0:H6], registers or memory.
.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, Z6, H0, H1, H2, H3, H4, H5, H6
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
	adcq	\H5, \Z5
	adcq	\H6, \Z6
.endm

// c <- a/2^448 mod p for a = 0+A < pR: reduce the low half to at most p, add
// the high half, which is below p, and subtract p once. A must not be based
// on %rdx; Z0..Z6 and T0..T2 must differ from %rax, %rcx, %rdx and %rsi.
.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, T2, P
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, 56+\A, 64+\A, 72+\A, 80+\A, 88+\A, 96+\A, 104+\A
	FINALC	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \Z0, \T1, \T2
.endm

// O[0:13] <- a^2 for a = 0+A, computing each cross product once. Words 1 and
// 2 are written to O early to free registers, so O must not overlap A and
// neither A nor O may be based on %rdx, Z0..Z9, T0 or T1.
.macro SQRN A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1
	// [w1:w7] <- a0 x [a1:a6]
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
	// Words 1 and 2 are final, so they free their registers.
	movq	\Z0, 8+\O
	movq	\Z1, 16+\O

	// [w3:w8] += a1 x [a2:a6]
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

	// [w5:w9] += a2 x [a3:a6]
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

	// [w7:w10] += a3 x [a4:a6]
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

	// [w9:w11] += a4 x [a5:a6]
	movq	32+\A, %rdx
	xorq	\Z0, \Z0
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	adcq	$0, \Z0

	// [w11:w12] += a5 x a6
	movq	40+\A, %rdx
	mulx	48+\A, \T0, \Z1
	addq	\T0, \Z0
	adcq	$0, \Z1

	// O <- 2 x [w1:w12] + [a0^2:a6^2], with w1 and w2 read back from O
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

// c <- a^2 (RDC = 0) or a^2/2^448 mod p (RDC = 1), for a = 0+A and c at %rdi.
// RDC = 1 builds a^2 in the 14 words of scratch at S and reduces it there;
// then Z0..Z9 must differ from %rax, %rcx, %rdx and %rsi.
.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
.if \RDC != 1
	SQRN	\A, 0(%rdi), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.else
	SQRN	\A, \S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
	FP_RDCN_LOW	\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \P
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC
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

// c <- a x b in Fp2 with u^2 = -1, for a = 0+A based on %rcx and b = 0+B based
// on %rsi. RDC = 0: c0 at %rdi and c1 at the pointer in 8+S. RDC = 1: c0 at
// %rdi and c1 at 56(%rdi), reduced, where c may alias a or b. S is ten words
// of scratch.
.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC, S
	// The corrections and FINALC overwrite %rcx and %rsi.
	movq	%rsi, 0+\S
	movq	%rcx, 16+\S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, 0
	movq	0+\S, %rsi
	movq	16+\S, %rcx
	movq	8+\S, %rdi
	MULM	\A, 56+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, 0
.else
	// c1 goes to the scratch space, since c0 still reads a1 and b1.
	movq	%rdi, 8+\S
	leaq	24+\S, %rdi
	MULM	\A, 56+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P, 1
	movq	0+\S, %rsi
	movq	16+\S, %rcx
	movq	8+\S, %rdi
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

// c <- a^2 in Fp2 with u^2 = -1, for a = 0+A based on %rsi:
// c0 = (a0 + a1) x (a0 - a1 + p), c1 = 2 x a0 x a1. RDC = 0: c0 at %rdi and
// c1 at the pointer in 168+S. RDC = 1: c0 at %rdi and c1 at 56(%rdi),
// reduced, where c may alias a. S is 23 words of scratch. Uses %rax, %rcx and
// %rdx, and overwrites %rsi when RDC = 1.
.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1, P, RDC, S
	// [0+S] <- a0 + a1, [112+S] <- 2 x a0, [56+S] <- a0 - a1 + p
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

	// c1 first: it is the last reader of a, and c0 only reads the scratch.
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
