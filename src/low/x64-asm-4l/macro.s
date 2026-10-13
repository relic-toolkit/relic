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
 * words, which needs p < 2^255, and FP2_MUL0_LOW reduces a signed value, which
 * needs 2p < 2^255.
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

// [Z0:Z4] <- A x [Z0, Z2, Z4, Z5], with Z5 as scratch.
.macro MULR A, Z0, Z1, Z2, Z3, Z4, Z5
	movq	0+\A, %rdx
	mulx	\Z0, \Z0, \Z1
	xorq	%rax, %rax
	mulx	\Z2, \Z3, \Z2
	adox	\Z3, \Z1
	mulx	\Z4, \Z4, \Z3
	adox	\Z4, \Z2
	mulx	\Z5, \Z5, \Z4
	adox	\Z5, \Z3
	adox	%rax, \Z4
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
.macro FP_MULM_LOW A, B, Z0, Z1, Z2, Z3, Z4, T0, T1, P, RDC
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
