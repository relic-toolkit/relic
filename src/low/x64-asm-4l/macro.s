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

/*
 * The interleaved Montgomery macros below keep intermediate results in N + 1
 * words, which needs p < 2^255.
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
#error "x64-asm-4l only supports FP_PRIME = 254 (BN_254) or 255 (PRIME_25519)"
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

/*
 * FP2_MUL0_LOW with RDC = 1 keeps the real part as a signed value in (-p, 2p),
 * which only fits RLC_FP_DIGS digits when 2p < 2^255, that is, p < 2^254.
 * FP_PRIME = 255 fails this, but its prime is 5 mod 8, so FP_QNRES rejects it
 * and the Fp2 assembly never runs for it.
 */
#if P3 < 0x4000000000000000
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

// [Z0:Z4] <- A x B, with Z5 as scratch.
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

// [Z0:Z4] += rdx x M, needs CF = OF = 0 and rax = 0.
.macro MULADD Z0, Z1, Z2, Z3, Z4, T0, T1, M
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
	adcx   %rax,\Z4
.endm

// [Z0:Z4] -= rdx x M.
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

// Final correction: c <- [Z4, Z0:Z2] - p if it does not borrow.
.macro FINALC Z0, Z1, Z2, Z3, Z4, T0, T1
	movq	\Z4, \Z3
	movq	\Z0, \T0
	movq	\Z1, \T1
	movq	\Z2, %rax
	subq	p0(%rip), \Z3
	sbbq	p1(%rip), \T0
	sbbq	p2(%rip), \T1
	sbbq	p3(%rip), %rax
	cmovc	\Z4, \Z3
	cmovc	\Z0, \T0
	cmovc	\Z1, \T1
	cmovc	\Z2, %rax
	movq	\Z3, 0(%rdi)
	movq	\T0, 8(%rdi)
	movq	\T1, 16(%rdi)
	movq	%rax, 24(%rdi)
.endm

// Continues A x B from [Z0:Z4] = a0 x B. With RDC = 1, interleaves the
// Montgomery reduction and writes A x B / 2^256 mod p; otherwise writes A x B.
.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [Z1:Z4] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	// [Z1:Z4, Z0] <- z += a1 x B
	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [Z2:Z4, Z0] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \P
.endif

	// [Z2:Z4, Z0:Z1] <- z += a2 x B
	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [Z3:Z4, Z0:Z1] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \P
.endif

	// [Z3:Z4, Z0:Z2] <- z += a3 x B
	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [Z4, Z0:Z2] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z4, 32(%rdi)
	movq	\Z0, 40(%rdi)
	movq	\Z1, 48(%rdi)
	movq	\Z2, 56(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1
.endif
.endm

// Continues a0 x b0 - a1 x b1 from [Z0:Z4] = a00 x b0, keeping z signed.
.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC
	movq	32+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 32+\B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [Z1:Z4] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z4
	sbbq	$0, \Z0

	// [Z1:Z4, Z0] <- z = a01 x b0 - a11 x b1 + z
	movq	8+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \B
	movq	40+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, 32+\B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [Z2:Z4, Z0] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	// [Z2:Z4, Z0:Z1] <- z = a02 x b0 - a12 x b1 + z
	movq	16+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \B
	movq	48+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, 32+\B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [Z3:Z4, Z0:Z1] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	// [Z3:Z4, Z0:Z2] <- z = a03 x b0 - a13 x b1 + z
	movq	24+\A, %rdx
	xorq	%rax, %rax
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	56+\A, %rdx
	MULSUB	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, 32+\B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [Z4, Z0:Z2] <- z = ((z0 x u0) x p + z)/2^64
	xorq	%rax, %rax
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	btq		$63, \Z2

	// Correction if result < 0
	movq	$0, \Z3
	movq	$0, \T0
	movq	$0, \T1
	movq	$0, %rax
	cmovc	p0(%rip), \Z3
	cmovc	p1(%rip), \T0
	cmovc	p2(%rip), \T1
	cmovc	p3(%rip), %rax
	addq	\Z3, \Z4
	adcq	\T0, \Z0
	adcq	\T1, \Z1
	adcq	%rax, \Z2
.if \RDC != 1
	movq	\Z4, 32(%rdi)
	movq	\Z0, 40(%rdi)
	movq	\Z1, 48(%rdi)
	movq	\Z2, 56(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1
.endif
.endm

// Continues a0 x b1 + a1 x b0 from [Z0:Z4] = a00 x b1.
.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC
	movq	32+\A, %rdx
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\Z0, 0(%rdi)
.else
	// [Z1:Z4] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	// [Z1:Z4, Z0] <- z = a01 x b1 + a11 x b0 + z
	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, 32+\B
	movq	40+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\Z1, 8(%rdi)
.else
	// [Z2:Z4, Z0] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z0, \T0, \T1, \P
.endif

	// [Z2:Z4, Z0:Z1] <- z = a02 x b1 + a12 x b0 + z
	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, 32+\B
	movq	48+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\Z2, 16(%rdi)
.else
	// [Z3:Z4, Z0:Z1] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z0, \Z1, \T0, \T1, \P
.endif

	// [Z3:Z4, Z0:Z2] <- z = a03 x b1 + a13 x b0 + z
	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, 32+\B
	movq	56+\A, %rdx
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\Z3, 24(%rdi)
.else
	// [Z4, Z0:Z2] <- z = ((z0 x u0) x p + z)/2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\Z4, 32(%rdi)
	movq	\Z0, 40(%rdi)
	movq	\Z1, 48(%rdi)
	movq	\Z2, 56(%rdi)
.else
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1
.endif
.endm

// Montgomery step on a window with no word above it:
// [Z1:Z3, Z0] <- ([Z0:Z3] + (Z0 x u0 mod 2^64) x p)/2^64.
// The window stays below 2^256 for p < 2^255, so no carry leaves it.
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
	// Z0 is zero here, so this cannot overflow.
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

// [Z0:Z3] <- [Z0:Z3]/2^256 mod p, at most p, by four Montgomery steps.
.macro RDCN Z0, Z1, Z2, Z3, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z0, \Z1, \Z2, \T0, \T1, \P
.endm

// [Z0:Z3] += [H0:H3], registers or memory.
.macro ADDH Z0, Z1, Z2, Z3, H0, H1, H2, H3
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
.endm

// c <- a/2^256 mod p for a = 0+A < pR: reduce the low half to at most p, add
// the high half, which is below p, and subtract p once. This needs 2p < 2^256.
// T1, T2 and T3 must differ from %rax, %rdx and the base register of A, except
// that T3 may be that base register.
.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, T0, T1, T2, T3, P
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	RDCN	\Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, 32+\A, 40+\A, 48+\A, 56+\A
	FINALC	\Z1, \Z2, \Z3, \T1, \Z0, \T2, \T3
.endm

// [Z0:Z7] <- a^2 with a = 0+A, computing each cross product once.
// The last word Z7 must be the base register of A.
.macro SQRN A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, T0, T1
	// [Z1:Z4] <- a0 x [a1:a3]
	movq	0+\A, %rdx
	mulx	8+\A, \Z1, \Z2
	mulx	16+\A, \T0, \Z3
	addq	\T0, \Z2
	mulx	24+\A, \T0, \Z4
	adcq	\T0, \Z3
	adcq	$0, \Z4

	// [Z3:Z5] += a1 x [a2:a3]
	movq	8+\A, %rdx
	xorq	\Z5, \Z5
	mulx	16+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	adcq	$0, \Z5

	// [Z5:Z6] += a2 x a3
	movq	16+\A, %rdx
	mulx	24+\A, \T0, \Z6
	addq	\T0, \Z5
	adcq	$0, \Z6

	// [Z0:Z7] <- 2 x [Z1:Z6] + [a0^2:a3^2]
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

// c <- a^2 (RDC = 0) or a^2/2^256 mod p (RDC = 1) at %rdi, for a = 0+A based
// on Z7. T0 and T1 must differ from %rdx, and T1 from %rax. With four words,
// SQRN followed by RDCN has a longer latency than the interleaved Montgomery
// multiplication, so RDC = 1 computes a x a instead.
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

// c <- a x b in Fp2 with u^2 = -1, for b = 0+B and a = 0+A based on registers
// other than %rax, %rdx and %rdi. RDC = 0: c0 at %rdi and c1 at the pointer in
// 0+S. RDC = 1: c0 at %rdi and c1 at 32(%rdi), reduced, where c may alias a or
// b. S is six words of scratch.
.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, 0
	movq	0+\S, %rdi
	MULM	\A, 32+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, 0
.else
	// c1 goes to the scratch space, since c0 still reads a1 and b1.
	movq	%rdi, 0+\S
	leaq	16+\S, %rdi
	MULM	\A, 32+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, 1
	movq	0+\S, %rdi
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P, 1
	movq	16+\S, \Z0
	movq	24+\S, \Z1
	movq	32+\S, \Z2
	movq	40+\S, \Z3
	movq	\Z0, 32(%rdi)
	movq	\Z1, 40(%rdi)
	movq	\Z2, 48(%rdi)
	movq	\Z3, 56(%rdi)
.endif
.endm

// c <- a^2 in Fp2 with u^2 = -1, for a = 0+A:
// c0 = (a0 + a1) x (a0 - a1 + p), c1 = 2 x a0 x a1. RDC = 0: c0 at %rdi and
// c1 at the pointer in 96+S. RDC = 1: c0 at %rdi and c1 at 32(%rdi),
// reduced, where c may alias a. S is 14 words of scratch. Uses %rax and %rdx.
// The real part is below 4p^2, so reducing it needs 4p < 2^256.
.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC, S
	// [0+S] <- a0 + a1, [32+S] <- a0 - a1 + p, [64+S] <- 2 x a0
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	\Z0, \Z4
	movq	\Z1, \T0
	movq	\Z2, \T1
	movq	\Z3, %rax
	subq	32+\A, \Z4
	sbbq	40+\A, \T0
	sbbq	48+\A, \T1
	sbbq	56+\A, %rax
	addq	0+\P, \Z4
	adcq	8+\P, \T0
	adcq	16+\P, \T1
	adcq	24+\P, %rax
	movq	\Z4, 32+\S
	movq	\T0, 40+\S
	movq	\T1, 48+\S
	movq	%rax, 56+\S
	movq	\Z0, \Z4
	movq	\Z1, \T0
	movq	\Z2, \T1
	movq	\Z3, %rax
	addq	32+\A, \Z4
	adcq	40+\A, \T0
	adcq	48+\A, \T1
	adcq	56+\A, %rax
	movq	\Z4, 0+\S
	movq	\T0, 8+\S
	movq	\T1, 16+\S
	movq	%rax, 24+\S
	addq	\Z0, \Z0
	adcq	\Z1, \Z1
	adcq	\Z2, \Z2
	adcq	\Z3, \Z3
	movq	\Z0, 64+\S
	movq	\Z1, 72+\S
	movq	\Z2, 80+\S
	movq	\Z3, 88+\S

	// c1 first: it is the last reader of a, and c0 only reads the scratch.
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
