/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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

#if FP_PRIME == 768
#define P0	0x591ADE1200800001
#define P1	0xACE2A12843C534B1
#define P2	0x9FBEDDEE98705380
#define P3	0x1429BCDA53E20A8F
#define P4	0x31B6221831F61A72
#define P5	0x828EC90E320E3793
#define P6	0x9AD532EA851862BD
#define P7	0x6A6D9D80470079AE
#define P8	0xBA1AF14A9BC88DBA
#define P9	0x172EC88A91CFC7D2
#define P10	0x3290395E476657BA
#define P11	0xFFFFFFE4FF400142
#define U0	0x471A9E12007FFFFF
#define BAR	0x8000000D806000CB
#define BARS	63
#define BARJ	11
#elif FP_PRIME == 766
/* AFG16-766, the prime picked for 766 bits. K16_766 is not supported. */
#define P0	0xF45D1E791E054605
#define P1	0xFCBC4220020A6592
#define P2	0x211730168CD3106C
#define P3	0xC81A3A94170A2E5A
#define P4	0x04A837318C7897B6
#define P5	0xA2902CAC0A117EAD
#define P6	0x4C8C62B406D882C8
#define P7	0xDC0F8D8300A6748A
#define P8	0x67D35D389C7BD43C
#define P9	0x89F38FC6E7249EF1
#define P10	0xC2E122127943E41E
#define P11	0x3FFFB8002607F379
#define U0	0xF282381A203F6933
#define BAR	0x8000900055F02428
#define BARS	61
#define BARJ	11
#elif FP_PRIME == 765
/* FM16-765 */
#define P0	0x1000EFC080000001
#define P1	0x0000000038223FF0
#define P2	0x0000000000000000
#define P3	0x0140000000000000
#define P4	0x93D3AA2586A9BB7B
#define P5	0x2C9088558A226AF0
#define P6	0x7071D6BA0697D5A1
#define P7	0xFE00400021385D1A
#define P8	0x1629227BB6527E4E
#define P9	0xD4A66E04AA631EEA
#define P10	0xBC5664C6F237BCB4
#define P11	0x166A30BEAF4CE221
#define U0	0xD000EFC07FFFFFFF
#define BAR	0xB6BC81C39E9E28BA
#define BARS	60
#define BARJ	11
#else
#error "x64-asm-12l supports only FP_PRIME = 765, 766 or 768."
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

/*
 * Stack frame of the multiplication and reduction functions. With 12 digits,
 * the accumulator takes 13 registers, the multiplier takes rdx and one more
 * register is left for the partial products, so the operand b, the pointers
 * and the constants live on the stack.
 */
#define BCPY	0(%rsp)
#define APTR	96(%rsp)
#define CPTR	104(%rsp)
#define ZERO	112(%rsp)
#define ONES	120(%rsp)
#define CARRY	128(%rsp)
#define FRAME	136

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

// [Z0:Z12] <- a0 x b, with a pointer to a in A.
.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12, T
	movq	\A, %rdx
	movq	0(%rdx), %rdx
	mulx	0+\B, \Z0, \Z1
	xorq	\T, \T
	mulx	8+\B, \T, \Z2
	adox	\T, \Z1
	mulx	16+\B, \T, \Z3
	adox	\T, \Z2
	mulx	24+\B, \T, \Z4
	adox	\T, \Z3
	mulx	32+\B, \T, \Z5
	adox	\T, \Z4
	mulx	40+\B, \T, \Z6
	adox	\T, \Z5
	mulx	48+\B, \T, \Z7
	adox	\T, \Z6
	mulx	56+\B, \T, \Z8
	adox	\T, \Z7
	mulx	64+\B, \T, \Z9
	adox	\T, \Z8
	mulx	72+\B, \T, \Z10
	adox	\T, \Z9
	mulx	80+\B, \T, \Z11
	adox	\T, \Z10
	mulx	88+\B, \T, \Z12
	adox	\T, \Z11
	adox	ZERO, \Z12
.endm

// [Z0:Z11, X] <- [Z0:Z11, CARRY] + rdx x M, where the free register X turns into
// the top word and CARRY is zero unless the prime fills the top bit.
// Needs CF = OF = 0 on entry.
.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, X, T, M
	mulx	0+\M, \T, \X
	adox	\T, \Z0
	adox	\X, \Z1
	mulx	8+\M, \T, \X
	adcx	\T, \Z1
	adox	\X, \Z2
	mulx	16+\M, \T, \X
	adcx	\T, \Z2
	adox	\X, \Z3
	mulx	24+\M, \T, \X
	adcx	\T, \Z3
	adox	\X, \Z4
	mulx	32+\M, \T, \X
	adcx	\T, \Z4
	adox	\X, \Z5
	mulx	40+\M, \T, \X
	adcx	\T, \Z5
	adox	\X, \Z6
	mulx	48+\M, \T, \X
	adcx	\T, \Z6
	adox	\X, \Z7
	mulx	56+\M, \T, \X
	adcx	\T, \Z7
	adox	\X, \Z8
	mulx	64+\M, \T, \X
	adcx	\T, \Z8
	adox	\X, \Z9
	mulx	72+\M, \T, \X
	adcx	\T, \Z9
	adox	\X, \Z10
	mulx	80+\M, \T, \X
	adcx	\T, \Z10
	adox	\X, \Z11
	mulx	88+\M, \T, \X
	adcx	\T, \Z11
	adox	ZERO, \X
	adcx	CARRY, \X
.endm

// [Z1:Z12] <- ([Z0:Z12] + (Z0 x U0 mod 2^64) x M) / 2^64, freeing Z0. The low
// word cancels, so its carry is Z0 != 0, which adding all-ones to Z0 yields.
// With Z12 blank, the top word is zero on entry and is left in Z0.
// Needs CF = OF = 0 on entry.
.macro MULRDC Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12, T, M
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T
	mulx	0+\M, \T, \T
	adcx	ONES, \Z0
	adox	\T, \Z1
	mulx	8+\M, \T, \Z0
	adcx	\T, \Z1
	adox	\Z0, \Z2
	mulx	16+\M, \T, \Z0
	adcx	\T, \Z2
	adox	\Z0, \Z3
	mulx	24+\M, \T, \Z0
	adcx	\T, \Z3
	adox	\Z0, \Z4
	mulx	32+\M, \T, \Z0
	adcx	\T, \Z4
	adox	\Z0, \Z5
	mulx	40+\M, \T, \Z0
	adcx	\T, \Z5
	adox	\Z0, \Z6
	mulx	48+\M, \T, \Z0
	adcx	\T, \Z6
	adox	\Z0, \Z7
	mulx	56+\M, \T, \Z0
	adcx	\T, \Z7
	adox	\Z0, \Z8
	mulx	64+\M, \T, \Z0
	adcx	\T, \Z8
	adox	\Z0, \Z9
	mulx	72+\M, \T, \Z0
	adcx	\T, \Z9
	adox	\Z0, \Z10
	mulx	80+\M, \T, \Z0
	adcx	\T, \Z10
	adox	\Z0, \Z11
	mulx	88+\M, \T, \Z0
	adcx	\T, \Z11
.ifb \Z12
	adox	ZERO, \Z0
	adcx	ZERO, \Z0
.else
	adox	\Z0, \Z12
	adcx	ZERO, \Z12
.endif
.endm

// Final correction: stores [C:Z0:Z11] - p if it does not borrow and [Z0:Z11]
// otherwise at the pointer in CPTR. C is blank when the input is below 2^768.
.macro FINALC Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, C
	movq	CPTR, %rdx
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
	subq	p0(%rip), \Z0
	sbbq	p1(%rip), \Z1
	sbbq	p2(%rip), \Z2
	sbbq	p3(%rip), \Z3
	sbbq	p4(%rip), \Z4
	sbbq	p5(%rip), \Z5
	sbbq	p6(%rip), \Z6
	sbbq	p7(%rip), \Z7
	sbbq	p8(%rip), \Z8
	sbbq	p9(%rip), \Z9
	sbbq	p10(%rip), \Z10
	sbbq	p11(%rip), \Z11
.ifnb \C
	sbbq	$0, \C
.endif
	cmovc	0(%rdx), \Z0
	cmovc	8(%rdx), \Z1
	cmovc	16(%rdx), \Z2
	cmovc	24(%rdx), \Z3
	cmovc	32(%rdx), \Z4
	cmovc	40(%rdx), \Z5
	cmovc	48(%rdx), \Z6
	cmovc	56(%rdx), \Z7
	cmovc	64(%rdx), \Z8
	cmovc	72(%rdx), \Z9
	cmovc	80(%rdx), \Z10
	cmovc	88(%rdx), \Z11
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
.endm

// Interleaved Montgomery multiplication after MULM, rotating the accumulator
// over Z0..Z12. With RDC = 0, it stores the double-precision product instead.
.macro FP_MULM_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12, T, P, RDC
.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z0, 0(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z0
	adox	ZERO, \Z0
	adcx	ZERO, \Z0
	movq	\Z0, CARRY
#endif
.endif

	// z += a1 x b
	movq	\A, %rdx
	movq	8(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z1, 8(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z1
	adox	ZERO, \Z1
	adcx	ZERO, \Z1
	movq	\Z1, CARRY
#endif
.endif

	// z += a2 x b
	movq	\A, %rdx
	movq	16(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z2, 16(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z2
	adox	ZERO, \Z2
	adcx	ZERO, \Z2
	movq	\Z2, CARRY
#endif
.endif

	// z += a3 x b
	movq	\A, %rdx
	movq	24(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z3, 24(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z3
	adox	ZERO, \Z3
	adcx	ZERO, \Z3
	movq	\Z3, CARRY
#endif
.endif

	// z += a4 x b
	movq	\A, %rdx
	movq	32(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z4, 32(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z4
	adox	ZERO, \Z4
	adcx	ZERO, \Z4
	movq	\Z4, CARRY
#endif
.endif

	// z += a5 x b
	movq	\A, %rdx
	movq	40(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z5, 40(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z5
	adox	ZERO, \Z5
	adcx	ZERO, \Z5
	movq	\Z5, CARRY
#endif
.endif

	// z += a6 x b
	movq	\A, %rdx
	movq	48(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z6, 48(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z6
	adox	ZERO, \Z6
	adcx	ZERO, \Z6
	movq	\Z6, CARRY
#endif
.endif

	// z += a7 x b
	movq	\A, %rdx
	movq	56(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z7, 56(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z7
	adox	ZERO, \Z7
	adcx	ZERO, \Z7
	movq	\Z7, CARRY
#endif
.endif

	// z += a8 x b
	movq	\A, %rdx
	movq	64(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z8, 64(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z8
	adox	ZERO, \Z8
	adcx	ZERO, \Z8
	movq	\Z8, CARRY
#endif
.endif

	// z += a9 x b
	movq	\A, %rdx
	movq	72(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z9, 72(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z9
	adox	ZERO, \Z9
	adcx	ZERO, \Z9
	movq	\Z9, CARRY
#endif
.endif

	// z += a10 x b
	movq	\A, %rdx
	movq	80(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z10, 80(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z10
	adox	ZERO, \Z10
	adcx	ZERO, \Z10
	movq	\Z10, CARRY
#endif
.endif

	// z += a11 x b
	movq	\A, %rdx
	movq	88(%rdx), %rdx
	xorq	\T, \T
	MULADD	\Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T, \B

.if \RDC != 1
	movq	CPTR, %rdx
	movq	\Z11, 88(%rdx)
.else
	// z = (z + (z0 x u0 mod 2^64) x p) / 2^64
	MULRDC	\Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T, \P
#if FP_PRIME == 768
	// The sum can reach 2^(64 * 13), so keep its carry.
	movq	$0, \Z11
	adox	ZERO, \Z11
	adcx	ZERO, \Z11
#endif
.endif

.if \RDC != 1
	movq	\Z12, 96(%rdx)
	movq	\Z0, 104(%rdx)
	movq	\Z1, 112(%rdx)
	movq	\Z2, 120(%rdx)
	movq	\Z3, 128(%rdx)
	movq	\Z4, 136(%rdx)
	movq	\Z5, 144(%rdx)
	movq	\Z6, 152(%rdx)
	movq	\Z7, 160(%rdx)
	movq	\Z8, 168(%rdx)
	movq	\Z9, 176(%rdx)
	movq	\Z10, 184(%rdx)
.else
#if FP_PRIME == 768
	FINALC	\Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11
#else
	FINALC	\Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10
#endif
.endif
.endm
