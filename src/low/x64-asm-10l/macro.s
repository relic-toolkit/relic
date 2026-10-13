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

/*
 * The constants below are for the prime that fp_param_set_any() picks: BLS12-P638
 * when FP_QNRES is defined and KSS18-P638 otherwise. BN-P638 and SG18-P638 are
 * not supported by this backend.
 */
#if FP_PRIME == 638 && defined(FP_QNRES)
/* BLS12-P638 */
#define P0	0xAAAAAAAABEAB000B
#define P1	0xEAF3FF000AAAAAAA
#define P2	0xAAAAAAAAAAAAAA93
#define P3	0x00000AC79600D2AB
#define P4	0x5C75D6C2AB000000
#define P5	0x3955555555529C00
#define P6	0x00631BBD42171501
#define P7	0xFC01DCDE95D40000
#define P8	0xE80015554DD25DB0
#define P9	0x3CB868653D300B3F
#define U0	0xFAD7AB621D14745D
#define BAR	0x86E9E19FD94C0210
#define BARS	61
#define BARJ	9
#elif FP_PRIME == 638
/* KSS18-P638 */
#define P0	0xB0BE48934E64EB1D
#define P1	0xFB8F59E264FB7A71
#define P2	0xDC8DBE9D09E2BBCF
#define P3	0x1ACCD9ACD070D120
#define P4	0x0FBC237576EC5F25
#define P5	0xBD29B9F3F83809B4
#define P6	0x5CC3342493BEF7B5
#define P7	0xBB534653BDD64BE8
#define P8	0x659ABF42A9FC767B
#define P9	0x30344028BB5A934E
#define U0	0x92071B32EE1AD0CB
#define BAR	0xA9F1AC5D7ED6C221
#define BARS	61
#define BARJ	9
#else
#error "x64-asm-10l only supports FP_PRIME = 638."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

/*
 * FP2_MUL0_LOW with RDC = 1 keeps the real part as a signed value in (-p, 2p),
 * which only fits RLC_FP_DIGS digits when 2p < 2^639, that is, p < 2^638.
 */
#if P9 < 0x4000000000000000
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

/*
 * The accumulator z has eleven digits Z0..Z10, which with T0, T1, rdx and the
 * base register of b take all fifteen registers, so the pointers to a and c
 * are read from the stack through the memory operands A and C. MULADD has no
 * zero register and clears T1 for its last carry instead.
 */
.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T
	movq	\A, %rdx
	movq	0(%rdx), %rdx
	mulx	0+\B, \Z0, \Z1
	mulx	8+\B, \T, \Z2
	addq	\T, \Z1
	mulx	16+\B, \T, \Z3
	adcq	\T, \Z2
	mulx	24+\B, \T, \Z4
	adcq	\T, \Z3
	mulx	32+\B, \T, \Z5
	adcq	\T, \Z4
	mulx	40+\B, \T, \Z6
	adcq	\T, \Z5
	mulx	48+\B, \T, \Z7
	adcq	\T, \Z6
	mulx	56+\B, \T, \Z8
	adcq	\T, \Z7
	mulx	64+\B, \T, \Z9
	adcq	\T, \Z8
	mulx	72+\B, \T, \Z10
	adcq	\T, \Z9
	adcq	$0, \Z10
.endm

.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, M
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
	mulx	72+\M, \T1, \T0
	adcx	\T1, \Z9
	adox	\T0, \Z10
	movq	$0, \T1
	adcx	\T1, \Z10
.endm

.macro MULSUB Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, M
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
	mulx	72+\M, \T1, \T0
	sbbq	\T1, \Z9
	sbbq	\T0, \Z10
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
	sbbq	$0, \Z10
.endm

// Final correction, keeping the input in C while p is subtracted.
.macro FINALC R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, C
	movq	\R0, 0+\C
	movq	\R1, 8+\C
	movq	\R2, 16+\C
	movq	\R3, 24+\C
	movq	\R4, 32+\C
	movq	\R5, 40+\C
	movq	\R6, 48+\C
	movq	\R7, 56+\C
	movq	\R8, 64+\C
	movq	\R9, 72+\C
	subq	p0(%rip), \R0
	sbbq	p1(%rip), \R1
	sbbq	p2(%rip), \R2
	sbbq	p3(%rip), \R3
	sbbq	p4(%rip), \R4
	sbbq	p5(%rip), \R5
	sbbq	p6(%rip), \R6
	sbbq	p7(%rip), \R7
	sbbq	p8(%rip), \R8
	sbbq	p9(%rip), \R9
	cmovc	0+\C, \R0
	cmovc	8+\C, \R1
	cmovc	16+\C, \R2
	cmovc	24+\C, \R3
	cmovc	32+\C, \R4
	cmovc	40+\C, \R5
	cmovc	48+\C, \R6
	cmovc	56+\C, \R7
	cmovc	64+\C, \R8
	cmovc	72+\C, \R9
	movq	\R0, 0+\C
	movq	\R1, 8+\C
	movq	\R2, 16+\C
	movq	\R3, 24+\C
	movq	\R4, 32+\C
	movq	\R5, 40+\C
	movq	\R6, 48+\C
	movq	\R7, 56+\C
	movq	\R8, 64+\C
	movq	\R9, 72+\C
.endm

// Montgomery step on a window with no word above it:
// [Z1:Z9, Z0] <- ([Z0:Z9] + (Z0 x u0 mod 2^64) x p)/2^64.
// The result is below 2^576 + p, so it fits the window and no carry leaves it.
.macro RDCSTEP Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
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
	adox	\T1, \Z9
	mulx	72+\P, \T0, \T1
	adcx	\T0, \Z9
	// Z0 is zero here, so this cannot overflow.
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

// [Z0:Z9] <- [Z0:Z9]/2^640 mod p, at most p, by ten Montgomery steps.
.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z5, \Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	RDCSTEP	\Z6, \Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	RDCSTEP	\Z7, \Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	RDCSTEP	\Z8, \Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
	RDCSTEP	\Z9, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endm

// [Z0:Z9] += [H0:H9], registers or memory.
.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, H0, H1, H2, H3, H4, H5, H6, H7, H8, H9
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
	adcq	\H5, \Z5
	adcq	\H6, \Z6
	adcq	\H7, \Z7
	adcq	\H8, \Z8
	adcq	\H9, \Z9
.endm

// c <- a/2^640 mod p for a = 0+A < pR and c at %rdi: reduce the low half to
// at most p, add the high half, which is below p, and subtract p once. A must
// not be based on %rdx, %rdi or the registers given.
.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	56+\A, \Z7
	movq	64+\A, \Z8
	movq	72+\A, \Z9
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, 80+\A, 88+\A, 96+\A, 104+\A, 112+\A, 120+\A, 128+\A, 136+\A, 144+\A, 152+\A
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, 0(%rdi)
.endm

// O[0:19] <- a^2 for a = 0+A, computing each cross product once. Each new top
// word takes the register of the lowest final word, which goes to O, so O must
// not overlap A and neither A nor O may be based on %rdx or the registers given.
.macro SQRN A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1
	// [w1:w10] <- a0 x [a1:a9]
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
	mulx	72+\A, \T0, \Z9
	adcq	\T0, \Z8
	adcq	$0, \Z9

	// [w3:w11] += a1 x [a2:a9]
	movq	\Z0, 8+\O
	movq	8+\A, %rdx
	xorq	\Z0, \Z0
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
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	adcq	$0, \Z0

	// [w5:w12] += a2 x [a3:a9]
	movq	\Z1, 16+\O
	movq	16+\A, %rdx
	xorq	\Z1, \Z1
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
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	adcq	$0, \Z1

	// [w7:w13] += a3 x [a4:a9]
	movq	\Z2, 24+\O
	movq	24+\A, %rdx
	xorq	\Z2, \Z2
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
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	adcq	$0, \Z2

	// [w9:w14] += a4 x [a5:a9]
	movq	\Z3, 32+\O
	movq	32+\A, %rdx
	xorq	\Z3, \Z3
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
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	adcq	$0, \Z3

	// [w11:w15] += a5 x [a6:a9]
	movq	\Z4, 40+\O
	movq	40+\A, %rdx
	xorq	\Z4, \Z4
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	adcq	$0, \Z4

	// [w13:w16] += a6 x [a7:a9]
	movq	\Z5, 48+\O
	movq	48+\A, %rdx
	xorq	\Z5, \Z5
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	adcq	$0, \Z5

	// [w15:w17] += a7 x [a8:a9]
	movq	\Z6, 56+\O
	movq	56+\A, %rdx
	xorq	\Z6, \Z6
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	adcq	$0, \Z6

	// [w17:w18] += a8 x a9
	movq	\Z7, 64+\O
	movq	64+\A, %rdx
	mulx	72+\A, \T0, \Z7
	addq	\T0, \Z6
	adcq	$0, \Z7

	// O <- 2 x [w1:w18] + [a0^2:a9^2], with w1..w8 read back from O
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
	movq	24+\O, \T0
	adcx	\T0, \T0
	adox	\T1, \T0
	movq	\T0, 24+\O
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	32+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 32+\O
	movq	40+\O, \T0
	adcx	\T0, \T0
	adox	\T1, \T0
	movq	\T0, 40+\O
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	48+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 48+\O
	movq	56+\O, \T0
	adcx	\T0, \T0
	adox	\T1, \T0
	movq	\T0, 56+\O
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	64+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 64+\O
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
	adcx	\Z6, \Z6
	adox	\T1, \Z6
	movq	\Z6, 136+\O
	movq	72+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z7, \Z7
	adox	\T0, \Z7
	movq	\Z7, 144+\O
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 152+\O
.endm

// c <- a^2 (RDC = 0) or a^2/2^640 mod p (RDC = 1), for a = 0+A and c at %rdi.
// RDC = 1 builds a^2 in the 20 words of scratch at S and reduces it there.
.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
.if \RDC != 1
	SQRN	\A, 0(%rdi), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.else
	SQRN	\A, \S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
	FP_RDCN_LOW	\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, C
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	// z = (z + ((z0 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P
.endif

	// z += a_1 x b
	xorq	\Z0, \Z0
	movq	\A, %rdx
	movq	8(%rdx), %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	// z = (z + ((z1 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \P
.endif

	// z += a_2 x b
	xorq	\Z1, \Z1
	movq	\A, %rdx
	movq	16(%rdx), %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	// z = (z + ((z2 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \P
.endif

	// z += a_3 x b
	xorq	\Z2, \Z2
	movq	\A, %rdx
	movq	24(%rdx), %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	// z = (z + ((z3 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// z += a_4 x b
	xorq	\Z3, \Z3
	movq	\A, %rdx
	movq	32(%rdx), %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	// z = (z + ((z4 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// z += a_5 x b
	xorq	\Z4, \Z4
	movq	\A, %rdx
	movq	40(%rdx), %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	// z = (z + ((z5 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	// z += a_6 x b
	xorq	\Z5, \Z5
	movq	\A, %rdx
	movq	48(%rdx), %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	// z = (z + ((z6 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	// z += a_7 x b
	xorq	\Z6, \Z6
	movq	\A, %rdx
	movq	56(%rdx), %rdx
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	// z = (z + ((z7 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	// z += a_8 x b
	xorq	\Z7, \Z7
	movq	\A, %rdx
	movq	64(%rdx), %rdx
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	// z = (z + ((z8 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T0
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	// z += a_9 x b
	xorq	\Z8, \Z8
	movq	\A, %rdx
	movq	72(%rdx), %rdx
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	// z = (z + ((z9 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z9, %rdx, \T0
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\C, \T0
	movq	\Z10, 80(\T0)
	movq	\Z0, 88(\T0)
	movq	\Z1, 96(\T0)
	movq	\Z2, 104(\T0)
	movq	\Z3, 112(\T0)
	movq	\Z4, 120(\T0)
	movq	\Z5, 128(\T0)
	movq	\Z6, 136(\T0)
	movq	\Z7, 144(\T0)
	movq	\Z8, 152(\T0)
.else
	movq	\C, \T0
	FINALC	\Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 0(\T0)
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, C
	// z -= a_10 x b_1
	movq	\A, %rdx
	movq	80(%rdx), %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	// z = (z + ((z0 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq	$63, \Z10
	sbbq	$0, \Z0

	// z += a_01 x b_0
	movq	\A, %rdx
	movq	8(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \B
	// z -= a_11 x b_1
	movq	\A, %rdx
	movq	88(%rdx), %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	// z = (z + ((z1 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq	$63, \Z0
	sbbq	$0, \Z1

	// z += a_02 x b_0
	movq	\A, %rdx
	movq	16(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \B
	// z -= a_12 x b_1
	movq	\A, %rdx
	movq	96(%rdx), %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	// z = (z + ((z2 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq	$63, \Z1
	sbbq	$0, \Z2

	// z += a_03 x b_0
	movq	\A, %rdx
	movq	24(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \B
	// z -= a_13 x b_1
	movq	\A, %rdx
	movq	104(%rdx), %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	// z = (z + ((z3 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq	$63, \Z2
	sbbq	$0, \Z3

	// z += a_04 x b_0
	movq	\A, %rdx
	movq	32(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	// z -= a_14 x b_1
	movq	\A, %rdx
	movq	112(%rdx), %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	// z = (z + ((z4 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq	$63, \Z3
	sbbq	$0, \Z4

	// z += a_05 x b_0
	movq	\A, %rdx
	movq	40(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	// z -= a_15 x b_1
	movq	\A, %rdx
	movq	120(%rdx), %rdx
	MULSUB	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	// z = (z + ((z5 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z5, \Z5
	btq	$63, \Z4
	sbbq	$0, \Z5

	// z += a_06 x b_0
	movq	\A, %rdx
	movq	48(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
	// z -= a_16 x b_1
	movq	\A, %rdx
	movq	128(%rdx), %rdx
	MULSUB	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	// z = (z + ((z6 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	xorq	\Z6, \Z6
	btq	$63, \Z5
	sbbq	$0, \Z6

	// z += a_07 x b_0
	movq	\A, %rdx
	movq	56(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
	// z -= a_17 x b_1
	movq	\A, %rdx
	movq	136(%rdx), %rdx
	MULSUB	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	// z = (z + ((z7 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	xorq	\Z7, \Z7
	btq	$63, \Z6
	sbbq	$0, \Z7

	// z += a_08 x b_0
	movq	\A, %rdx
	movq	64(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
	// z -= a_18 x b_1
	movq	\A, %rdx
	movq	144(%rdx), %rdx
	MULSUB	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	// z = (z + ((z8 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif
	xorq	\Z8, \Z8
	btq	$63, \Z7
	sbbq	$0, \Z8

	// z += a_09 x b_0
	movq	\A, %rdx
	movq	72(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
	// z -= a_19 x b_1
	movq	\A, %rdx
	movq	152(%rdx), %rdx
	MULSUB	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	// z = (z + ((z9 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z9, %rdx, \T0
	xorq	\T1, \T1
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif

	// Add p if the result is negative. Only adcx touches the flags, so SF
	// keeps the sign through the chain.
	testq	\Z8, \Z8
	movq	$0, \T0
	cmovs	p0(%rip), \T0
	adcx	\T0, \Z10
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
	movq	$0, \T1
	cmovs	p9(%rip), \T1
	adcx	\T1, \Z8
.if \RDC != 1
	movq	\C, \T0
	movq	\Z10, 80(\T0)
	movq	\Z0, 88(\T0)
	movq	\Z1, 96(\T0)
	movq	\Z2, 104(\T0)
	movq	\Z3, 112(\T0)
	movq	\Z4, 120(\T0)
	movq	\Z5, 128(\T0)
	movq	\Z6, 136(\T0)
	movq	\Z7, 144(\T0)
	movq	\Z8, 152(\T0)
.else
	movq	\C, \T0
	FINALC	\Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 0(\T0)
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, C
	// z += a_10 x b_0
	movq	\A, %rdx
	movq	80(%rdx), %rdx
	xorq	\T1, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	// z = (z + ((z0 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T0
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P
.endif

	// z += a_01 x b_1 + a_11 x b_0
	xorq	\Z0, \Z0
	movq	\A, %rdx
	movq	8(%rdx), %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	88(%rdx), %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	// z = (z + ((z1 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T0
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \P
.endif

	// z += a_02 x b_1 + a_12 x b_0
	xorq	\Z1, \Z1
	movq	\A, %rdx
	movq	16(%rdx), %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	96(%rdx), %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	// z = (z + ((z2 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T0
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \P
.endif

	// z += a_03 x b_1 + a_13 x b_0
	xorq	\Z2, \Z2
	movq	\A, %rdx
	movq	24(%rdx), %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	104(%rdx), %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	// z = (z + ((z3 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T0
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	// z += a_04 x b_1 + a_14 x b_0
	xorq	\Z3, \Z3
	movq	\A, %rdx
	movq	32(%rdx), %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	112(%rdx), %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	// z = (z + ((z4 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T0
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	// z += a_05 x b_1 + a_15 x b_0
	xorq	\Z4, \Z4
	movq	\A, %rdx
	movq	40(%rdx), %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	120(%rdx), %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	// z = (z + ((z5 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T0
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	// z += a_06 x b_1 + a_16 x b_0
	xorq	\Z5, \Z5
	movq	\A, %rdx
	movq	48(%rdx), %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	128(%rdx), %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	// z = (z + ((z6 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T0
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	// z += a_07 x b_1 + a_17 x b_0
	xorq	\Z6, \Z6
	movq	\A, %rdx
	movq	56(%rdx), %rdx
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	136(%rdx), %rdx
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	// z = (z + ((z7 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T0
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	// z += a_08 x b_1 + a_18 x b_0
	xorq	\Z7, \Z7
	movq	\A, %rdx
	movq	64(%rdx), %rdx
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	144(%rdx), %rdx
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	// z = (z + ((z8 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T0
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	// z += a_09 x b_1 + a_19 x b_0
	xorq	\Z8, \Z8
	movq	\A, %rdx
	movq	72(%rdx), %rdx
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, 80+\B
	movq	\A, %rdx
	movq	152(%rdx), %rdx
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	// z = (z + ((z9 x u0) mod 2^64) x p) / 2^64
	movq	$U0, %rdx
	mulx	\Z9, %rdx, \T0
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\C, \T0
	movq	\Z10, 80(\T0)
	movq	\Z0, 88(\T0)
	movq	\Z1, 96(\T0)
	movq	\Z2, 104(\T0)
	movq	\Z3, 112(\T0)
	movq	\Z4, 120(\T0)
	movq	\Z5, 128(\T0)
	movq	\Z6, 136(\T0)
	movq	\Z7, 144(\T0)
	movq	\Z8, 152(\T0)
.else
	movq	\C, \T0
	FINALC	\Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, 0(\T0)
.endif
.endm

// c <- a x b in Fp2 with u^2 = -1, for a at the pointer in A, a stack slot, and
// b = 0+B. RDC = 0: c0 at the pointer in 0+S and c1 at the pointer in 16+S.
// RDC = 1: c0 at the pointer in 0+S and c1 after it, reduced, where c may
// alias a or b. S is 13 words of scratch, and A may be 8+S.
.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, 0, 0+\S
	MULM	\A, 80+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, 0, 16+\S
.else
	// c1 goes to the scratch space, since c0 still reads a1 and b1.
	leaq	24+\S, \T0
	movq	\T0, 16+\S
	MULM	\A, 80+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, 1, 16+\S
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, 1, 0+\S
	movq	0+\S, \T0
	movq	24+\S, \Z0
	movq	32+\S, \Z1
	movq	40+\S, \Z2
	movq	48+\S, \Z3
	movq	56+\S, \Z4
	movq	64+\S, \Z5
	movq	72+\S, \Z6
	movq	80+\S, \Z7
	movq	88+\S, \Z8
	movq	96+\S, \Z9
	movq	\Z0, 80(\T0)
	movq	\Z1, 88(\T0)
	movq	\Z2, 96(\T0)
	movq	\Z3, 104(\T0)
	movq	\Z4, 112(\T0)
	movq	\Z5, 120(\T0)
	movq	\Z6, 128(\T0)
	movq	\Z7, 136(\T0)
	movq	\Z8, 144(\T0)
	movq	\Z9, 152(\T0)
.endif
.endm

// c <- a^2 in Fp2 with u^2 = -1, for a = 0+A based on a register other than
// the ones given: c0 = (a0 + a1) x (a0 - a1 + p), c1 = 2 x a0 x a1. RDC = 0:
// c0 at the pointer in 0+S and c1 at the pointer in 8+S. RDC = 1: c0 at the
// pointer in 0+S and c1 after it, reduced, where c may alias a. S is 34 words
// of scratch.
.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, S
	// [32+S] <- a0 + a1, [192+S] <- 2 x a0, [112+S] <- a0 - a1 + p
	movq	0+\A, \Z0
	addq	80+\A, \Z0
	movq	\Z0, 32+\S
	movq	8+\A, \Z0
	adcq	88+\A, \Z0
	movq	\Z0, 40+\S
	movq	16+\A, \Z0
	adcq	96+\A, \Z0
	movq	\Z0, 48+\S
	movq	24+\A, \Z0
	adcq	104+\A, \Z0
	movq	\Z0, 56+\S
	movq	32+\A, \Z0
	adcq	112+\A, \Z0
	movq	\Z0, 64+\S
	movq	40+\A, \Z0
	adcq	120+\A, \Z0
	movq	\Z0, 72+\S
	movq	48+\A, \Z0
	adcq	128+\A, \Z0
	movq	\Z0, 80+\S
	movq	56+\A, \Z0
	adcq	136+\A, \Z0
	movq	\Z0, 88+\S
	movq	64+\A, \Z0
	adcq	144+\A, \Z0
	movq	\Z0, 96+\S
	movq	72+\A, \Z0
	adcq	152+\A, \Z0
	movq	\Z0, 104+\S
	movq	0+\A, \Z0
	addq	\Z0, \Z0
	movq	\Z0, 192+\S
	movq	8+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 200+\S
	movq	16+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 208+\S
	movq	24+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 216+\S
	movq	32+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 224+\S
	movq	40+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 232+\S
	movq	48+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 240+\S
	movq	56+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 248+\S
	movq	64+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 256+\S
	movq	72+\A, \Z0
	adcq	\Z0, \Z0
	movq	\Z0, 264+\S
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	56+\A, \Z7
	movq	64+\A, \Z8
	movq	72+\A, \Z9
	subq	80+\A, \Z0
	sbbq	88+\A, \Z1
	sbbq	96+\A, \Z2
	sbbq	104+\A, \Z3
	sbbq	112+\A, \Z4
	sbbq	120+\A, \Z5
	sbbq	128+\A, \Z6
	sbbq	136+\A, \Z7
	sbbq	144+\A, \Z8
	sbbq	152+\A, \Z9
	addq	0+\P, \Z0
	adcq	8+\P, \Z1
	adcq	16+\P, \Z2
	adcq	24+\P, \Z3
	adcq	32+\P, \Z4
	adcq	40+\P, \Z5
	adcq	48+\P, \Z6
	adcq	56+\P, \Z7
	adcq	64+\P, \Z8
	adcq	72+\P, \Z9
	movq	\Z0, 112+\S
	movq	\Z1, 120+\S
	movq	\Z2, 128+\S
	movq	\Z3, 136+\S
	movq	\Z4, 144+\S
	movq	\Z5, 152+\S
	movq	\Z6, 160+\S
	movq	\Z7, 168+\S
	movq	\Z8, 176+\S
	movq	\Z9, 184+\S
	leaq	32+\S, \T0
	movq	\T0, 16+\S
	leaq	192+\S, \T0
	movq	\T0, 24+\S
.if \RDC == 1
	movq	0+\S, \T0
	addq	$80, \T0
	movq	\T0, 8+\S
.endif

	// c1 first: it is the last reader of a, and c0 only reads the scratch.
	MULM	24+\S, 80+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP_MUL_LOW	24+\S, 80+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, \RDC, 8+\S
	MULM	16+\S, 112+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP_MUL_LOW	16+\S, 112+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, \RDC, 0+\S
.endm
