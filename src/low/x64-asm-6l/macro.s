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
#define BAR	0xDEE640A79148522C
#define BARS	9
#elif FP_PRIME == 377
#define P0	0x8508C00000000001
#define P1	0x170B5D4430000000
#define P2	0x1EF3622FBA094800
#define P3	0x1A22D9F300F5138F
#define P4	0xC63B05C06CA1493B
#define P5	0X01AE3A4617C510EA
#define U0	0x8508BFFFFFFFFFFF
#define BAR	0x98542343310183A5
#define BARS	56
#elif FP_PRIME == 354
#define P0	0x470948C8C6AAAB1D
#define P1	0x2E5DA80FED8491B9
#define P2	0x8E6E049BE3926C48
#define P3	0xA1928ADE1A404A33
#define P4	0xEA98F0A5315F4B6B
#define P5	0x1428C74
#define U0	0xE03977E479F290CB
#define BAR	0xCB2E86F72F80D144
#define BARS	24
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
#endif


#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

/*
 * FP2_MUL0_LOW with RDC = 1 keeps the real part as a signed value in (-p, 2p),
 * which only fits RLC_FP_DIGS digits when 2p < 2^383, that is, p < 2^382.
 */
#if P5 < 0x4000000000000000
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
	sbbq	$0, \Z6
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

// Montgomery step on a window with no word above it:
// [Z1:Z5, Z0] <- ([Z0:Z5] + (Z0 x u0 mod 2^64) x p)/2^64.
// The window stays below 2^384 for p < 2^383, so no carry leaves it.
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
	// Z0 is zero here, so this cannot overflow.
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

// [Z0:Z5] <- [Z0:Z5]/2^384 mod p, at most p, by six Montgomery steps.
.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z5, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z5, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endm

// [Z0:Z5] += [H0:H5], registers or memory.
.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, H0, H1, H2, H3, H4, H5
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
	adcq	\H5, \Z5
.endm

// c <- a/2^384 mod p for a = 0+A < pR: reduce the low half to at most p, add
// the high half, which is below p, and subtract p once. A must be based on
// %rsi; T0, T1 and T2 must differ from %rax, %rdx and %rsi.
.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, T0, T1, T2, P
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, 48+\A, 56+\A, 64+\A, 72+\A, 80+\A, 88+\A
	FINALC	\Z1, \Z2, \Z3, \Z4, \Z5, \T0, \Z0, \T1, \T2
.endm

// [Z0:Z11] <- a^2 with a = 0+A, computing each cross product once.
// The last word Z11 must be the base register of A.
.macro SQRN A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1
	// [Z1:Z6] <- a0 x [a1:a5]
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

	// [Z3:Z7] += a1 x [a2:a5]
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

	// [Z5:Z8] += a2 x [a3:a5]
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

	// [Z7:Z9] += a3 x [a4:a5]
	movq	24+\A, %rdx
	xorq	\Z9, \Z9
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	adcq	$0, \Z9

	// [Z9:Z10] += a4 x a5
	movq	32+\A, %rdx
	mulx	40+\A, \T0, \Z10
	addq	\T0, \Z9
	adcq	$0, \Z10

	// [Z0:Z11] <- 2 x [Z1:Z10] + [a0^2:a5^2]
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

// c <- a^2 (RDC = 0) or a^2/2^384 mod p (RDC = 1), for a = 0+A based on Z11.
// Expects c on top of the stack and pops it before storing.
.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, P, RDC
	SQRN	\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1
.if \RDC != 1
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
	// The low half reduces to at most p and the high half is below p.
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11
	popq	%rdi
	FINALC	\Z1, \Z2, \Z3, \Z4, \Z5, \T1, \Z0, \Z6, \Z7
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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
	xorq	%rax, %rax
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

// c <- a x b in Fp2 with u^2 = -1, for b = 0+B based on %rsi and a = 0+A
// based on a register other than %rax, %rdx, %rsi and %rdi. RDC = 0: c0 at %rdi and c1 at the pointer in 8+S. RDC = 1: c0 at %rdi
// and c1 at 48(%rdi), reduced, where c may alias a or b. S is eight words of
// scratch.
.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC, S
	movq	%rsi, 0+\S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, 0
	movq	0+\S, %rsi
	movq	8+\S, %rdi
	MULM	\A, 48+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, 0
.else
	// c1 goes to the scratch space, since c0 still reads a1 and b1.
	movq	%rdi, 8+\S
	leaq	16+\S, %rdi
	MULM	\A, 48+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P, 1
	movq	0+\S, %rsi
	movq	8+\S, %rdi
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

// c <- a^2 in Fp2 with u^2 = -1, for a = 0+A based on %rsi:
// c0 = (a0 + a1) x (a0 - a1 + p), c1 = 2 x a0 x a1. RDC = 0: c0 at %rdi and
// c1 at the pointer in 144+S. RDC = 1: c0 at %rdi and c1 at 48(%rdi),
// reduced, where c may alias a. S is 20 words of scratch. Uses %rax, %rcx
// and %rdx.
.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, T0, T1, P, RDC, S
	// [0+S] <- a0 + a1, [48+S] <- a0 - a1 + p, [96+S] <- 2 x a0
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	\Z0, \Z6
	movq	\Z1, \T0
	movq	\Z2, \T1
	movq	\Z3, %rax
	movq	\Z4, %rcx
	movq	\Z5, %rdx
	subq	48+\A, \Z6
	sbbq	56+\A, \T0
	sbbq	64+\A, \T1
	sbbq	72+\A, %rax
	sbbq	80+\A, %rcx
	sbbq	88+\A, %rdx
	addq	0+\P, \Z6
	adcq	8+\P, \T0
	adcq	16+\P, \T1
	adcq	24+\P, %rax
	adcq	32+\P, %rcx
	adcq	40+\P, %rdx
	movq	\Z6, 48+\S
	movq	\T0, 56+\S
	movq	\T1, 64+\S
	movq	%rax, 72+\S
	movq	%rcx, 80+\S
	movq	%rdx, 88+\S
	movq	\Z0, \Z6
	movq	\Z1, \T0
	movq	\Z2, \T1
	movq	\Z3, %rax
	movq	\Z4, %rcx
	movq	\Z5, %rdx
	addq	48+\A, \Z6
	adcq	56+\A, \T0
	adcq	64+\A, \T1
	adcq	72+\A, %rax
	adcq	80+\A, %rcx
	adcq	88+\A, %rdx
	movq	\Z6, 0+\S
	movq	\T0, 8+\S
	movq	\T1, 16+\S
	movq	%rax, 24+\S
	movq	%rcx, 32+\S
	movq	%rdx, 40+\S
	addq	\Z0, \Z0
	adcq	\Z1, \Z1
	adcq	\Z2, \Z2
	adcq	\Z3, \Z3
	adcq	\Z4, \Z4
	adcq	\Z5, \Z5
	movq	\Z0, 96+\S
	movq	\Z1, 104+\S
	movq	\Z2, 112+\S
	movq	\Z3, 120+\S
	movq	\Z4, 128+\S
	movq	\Z5, 136+\S

	// c1 first: it is the last reader of a, and c0 only reads the scratch.
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
