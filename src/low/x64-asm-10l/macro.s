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

.macro FP_MULM_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, C
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
