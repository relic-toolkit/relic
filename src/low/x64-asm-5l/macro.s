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
 * @ingroup fp
 */

#if FP_PRIME == 315
#define P0	0x6FE802FF40300001
#define P1	0x421EE5DA52BDE502
#define P2	0xDEC1D01AA27A1AE0
#define P3	0xD3F7498BE97C5EAF
#define P4	0x04C23A02B586D650
#define U0	0x702FF9FF402FFFFF
#define BAR	0xD72F573970571ED0
#define BARS	58
#define BARJ	4
#elif FP_PRIME == 317
#define P0	0x8D512E565DAB2AAB
#define P1	0xD6F339E43424BF7E
#define P2	0x169A61E684C73446
#define P3	0xF28FC5A0B7F9D039
#define P4	0x1058CA226F60892C
#define U0	0x55B5E0028B047FFD
#define BAR	0xFA91822BBE91B750
#define BARS	60
#define BARJ	4
#else
#error "x64-asm-5l supports FP_PRIME = 315 or 317 only."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

/*
 * FP2_MUL0_LOW with RDC = 1 keeps the real part as a signed value in (-p, 2p),
 * which only fits RLC_FP_DIGS digits when 2p < 2^319, that is, p < 2^318.
 */
#if P4 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

/* The Fp2 functions read both coordinates from one contiguous vector. */
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
	sbbq	$0, \Z5
	mulx	0+\M, \T1, \T0
	subq	\T1, \Z0
	sbbq	\T0, \Z1
	mulx	16+\M, \T1, \T0
	sbbq	\T1, \Z2
	sbbq	\T0, \Z3
	mulx	32+\M, \T1, \T0
	sbbq	\T1, \Z4
	sbbq	\T0, \Z5
	sbbq	$0, \T0
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

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P, RDC
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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
// Montgomery step on a window with no word above it:
// [Z1:Z4, Z0] <- ([Z0:Z4] + (Z0 x u0 mod 2^64) x p)/2^64.
// The window stays below 2^320 for p < 2^319, so no carry leaves it.
.macro RDCSTEP Z0, Z1, Z2, Z3, Z4, T0, T1, P
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
	// Z0 is zero here, so this cannot overflow.
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

// [Z0:Z4] <- [Z0:Z4]/2^320 mod p, at most p, by five Montgomery steps.
.macro RDCN Z0, Z1, Z2, Z3, Z4, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endm

// [Z0:Z4] += [H0:H4], registers or memory.
.macro ADDH Z0, Z1, Z2, Z3, Z4, H0, H1, H2, H3, H4
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
.endm

// c <- a/2^320 mod p for a = 0+A < pR: reduce the low half to at most p, add
// the high half, which is below p, and subtract p once. This needs 2p < 2^320.
// T0 and T1 must differ from %rdx and the base register of A; T1, T2 and T3
// must differ from %rcx and %rdx, and T2 may be the base register of A.
.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, T0, T1, T2, T3, P
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, 40+\A, 48+\A, 56+\A, 64+\A, 72+\A
	FINALC	\Z1, \Z2, \Z3, \Z4, \T1, \Z0, \T2, \T3
.endm

// [Z0:Z9] <- a^2 with a = 0+A, computing each cross product once.
// The last word Z9 must be the base register of A.
.macro SQRN A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1
	// [Z1:Z5] <- a0 x [a1:a4]
	movq	0+\A, %rdx
	mulx	8+\A, \Z1, \Z2
	mulx	16+\A, \T0, \Z3
	addq	\T0, \Z2
	mulx	24+\A, \T0, \Z4
	adcq	\T0, \Z3
	mulx	32+\A, \T0, \Z5
	adcq	\T0, \Z4
	adcq	$0, \Z5

	// [Z3:Z6] += a1 x [a2:a4]
	movq	8+\A, %rdx
	xorq	\Z6, \Z6
	mulx	16+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	adcq	$0, \Z6

	// [Z5:Z7] += a2 x [a3:a4]
	movq	16+\A, %rdx
	xorq	\Z7, \Z7
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	adcq	$0, \Z7

	// [Z7:Z8] += a3 x a4
	movq	24+\A, %rdx
	mulx	32+\A, \T0, \Z8
	addq	\T0, \Z7
	adcq	$0, \Z8

	// [Z0:Z9] <- 2 x [Z1:Z8] + [a0^2:a4^2]
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
	movq	$0, \Z9
	adcx	\Z8, \Z8
	adox	\T0, \Z8
	adcx	\Z9, \Z9
	adox	\T1, \Z9
.endm

// c <- a^2 (RDC = 0) or a^2/2^320 mod p (RDC = 1) at %rdi, for a = 0+A based
// on Z9. T0 and T1 must differ from %rdx, and Z5, Z6 and Z7 from %rcx.
.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC
	SQRN	\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.if \RDC != 1
	movq	\Z0, 0(%rdi)
	movq	\Z1, 8(%rdi)
	movq	\Z2, 16(%rdi)
	movq	\Z3, 24(%rdi)
	movq	\Z4, 32(%rdi)
	movq	\Z5, 40(%rdi)
	movq	\Z6, 48(%rdi)
	movq	\Z7, 56(%rdi)
	movq	\Z8, 64(%rdi)
	movq	\Z9, 72(%rdi)
.else
	// The low half reduces to at most p and the high half is below p.
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9
	FINALC	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \Z6, \Z7
.endif
.endm

// c <- a x b in Fp2 with u^2 = -1, for b = 0+B and a = 0+A based on registers
// other than %rax, %rcx, %rdx and %rdi. RDC = 0: c0 at %rdi and c1 at the
// pointer in 0+S. RDC = 1: c0 at %rdi and c1 at 40(%rdi), reduced, where c may
// alias a or b. S is six words of scratch.
.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P, 0
	movq	0+\S, %rdi
	MULM	\A, 40+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P, 0
.else
	// c1 goes to the scratch space, since c0 still reads a1 and b1.
	movq	%rdi, 0+\S
	leaq	8+\S, %rdi
	MULM	\A, 40+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P, 1
	movq	0+\S, %rdi
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P, 1
	movq	8+\S, \Z0
	movq	16+\S, \Z1
	movq	24+\S, \Z2
	movq	32+\S, \Z3
	movq	40+\S, \Z4
	movq	\Z0, 40(%rdi)
	movq	\Z1, 48(%rdi)
	movq	\Z2, 56(%rdi)
	movq	\Z3, 64(%rdi)
	movq	\Z4, 72(%rdi)
.endif
.endm

// c <- a^2 in Fp2 with u^2 = -1, for a = 0+A based on a register other than
// %rax, %rcx and %rdx: c0 = (a0 + a1) x (a0 - a1 + p), c1 = 2 x a0 x a1.
// RDC = 0: c0 at %rdi and c1 at the pointer in 120+S. RDC = 1: c0 at %rdi and
// c1 at 40(%rdi), reduced, where c may alias a. S is 17 words of scratch.
// The real part is below 4p^2, so reducing it needs 4p < 2^320.
.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P, RDC, S
	// [0+S] <- a0 + a1, [40+S] <- a0 - a1 + p, [80+S] <- 2 x a0
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	\Z0, \Z5
	movq	\Z1, \T0
	movq	\Z2, \T1
	movq	\Z3, %rax
	movq	\Z4, %rcx
	subq	40+\A, \Z5
	sbbq	48+\A, \T0
	sbbq	56+\A, \T1
	sbbq	64+\A, %rax
	sbbq	72+\A, %rcx
	addq	0+\P, \Z5
	adcq	8+\P, \T0
	adcq	16+\P, \T1
	adcq	24+\P, %rax
	adcq	32+\P, %rcx
	movq	\Z5, 40+\S
	movq	\T0, 48+\S
	movq	\T1, 56+\S
	movq	%rax, 64+\S
	movq	%rcx, 72+\S
	movq	\Z0, \Z5
	movq	\Z1, \T0
	movq	\Z2, \T1
	movq	\Z3, %rax
	movq	\Z4, %rcx
	addq	40+\A, \Z5
	adcq	48+\A, \T0
	adcq	56+\A, \T1
	adcq	64+\A, %rax
	adcq	72+\A, %rcx
	movq	\Z5, 0+\S
	movq	\T0, 8+\S
	movq	\T1, 16+\S
	movq	%rax, 24+\S
	movq	%rcx, 32+\S
	addq	\Z0, \Z0
	adcq	\Z1, \Z1
	adcq	\Z2, \Z2
	adcq	\Z3, \Z3
	adcq	\Z4, \Z4
	movq	\Z0, 80+\S
	movq	\Z1, 88+\S
	movq	\Z2, 96+\S
	movq	\Z3, 104+\S
	movq	\Z4, 112+\S

	// c1 first: it is the last reader of a, and c0 only reads the scratch.
.if \RDC != 1
	movq	%rdi, 128+\S
	movq	120+\S, %rdi
.else
	addq	$40, %rdi
.endif
	MULM	80+\S, 40+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0
	FP_MUL_LOW	80+\S, 40+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P, \RDC
.if \RDC != 1
	movq	128+\S, %rdi
.else
	subq	$40, %rdi
.endif
	MULM	0+\S, 40+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0
	FP_MUL_LOW	0+\S, 40+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P, \RDC
.endm
