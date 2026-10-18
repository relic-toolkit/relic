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

#if FP_PRIME == 638 && defined(FP_QNRES)
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
#error "x64-asm-10l supports only FP_PRIME = 638."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

#if P9 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

#if P9 < 0x5555555555555555
#define FP2_SQR_RDC
#endif

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

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11
	movq	0+\A, %rdx
	mulx	0+\B, \Z0, \Z1
	mulx	8+\B, \Z11, \Z2
	addq	\Z11, \Z1
	mulx	16+\B, \Z11, \Z3
	adcq	\Z11, \Z2
	mulx	24+\B, \Z11, \Z4
	adcq	\Z11, \Z3
	mulx	32+\B, \Z11, \Z5
	adcq	\Z11, \Z4
	mulx	40+\B, \Z11, \Z6
	adcq	\Z11, \Z5
	mulx	48+\B, \Z11, \Z7
	adcq	\Z11, \Z6
	mulx	56+\B, \Z11, \Z8
	adcq	\Z11, \Z7
	mulx	64+\B, \Z11, \Z9
	adcq	\Z11, \Z8
	mulx	72+\B, \Z11, \Z10
	adcq	\Z11, \Z9
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

.macro FINALC V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, C0, C1, C2, C3, D
	movq	\V0, 0+\D
	movq	\V1, 8+\D
	movq	\V2, 16+\D
	movq	\V3, 24+\D
	movq	\V4, 32+\D
	movq	\V5, 40+\D
	movq	\V6, \C0
	movq	\V7, \C1
	movq	\V8, \C2
	movq	\V9, \C3
	subq	p0(%rip), \V0
	sbbq	p1(%rip), \V1
	sbbq	p2(%rip), \V2
	sbbq	p3(%rip), \V3
	sbbq	p4(%rip), \V4
	sbbq	p5(%rip), \V5
	sbbq	p6(%rip), \C0
	sbbq	p7(%rip), \C1
	sbbq	p8(%rip), \C2
	sbbq	p9(%rip), \C3
	cmovc	0+\D, \V0
	cmovc	8+\D, \V1
	cmovc	16+\D, \V2
	cmovc	24+\D, \V3
	cmovc	32+\D, \V4
	cmovc	40+\D, \V5
	cmovc	\V6, \C0
	cmovc	\V7, \C1
	cmovc	\V8, \C2
	cmovc	\V9, \C3
	movq	\V0, 0+\D
	movq	\V1, 8+\D
	movq	\V2, 16+\D
	movq	\V3, 24+\D
	movq	\V4, 32+\D
	movq	\V5, 40+\D
	movq	\C0, 48+\D
	movq	\C1, 56+\D
	movq	\C2, 64+\D
	movq	\C3, 72+\D
.endm

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
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

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

.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, C0, C1, C2, C3
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
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \C0, \C1, \C2, \C3, 0(%rdi)
.endm

.macro SQRN A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1
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
	movq	\Z0, 8+\O
	movq	\Z1, 16+\O

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
	movq	\Z2, 24+\O
	movq	\Z3, 32+\O

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
	movq	\Z4, 40+\O
	movq	\Z5, 48+\O

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
	movq	\Z6, 56+\O
	movq	\Z7, 64+\O

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

	movq	56+\A, %rdx
	xorq	\Z6, \Z6
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	adcq	$0, \Z6

	movq	64+\A, %rdx
	mulx	72+\A, \T0, \Z7
	addq	\T0, \Z6
	adcq	$0, \Z7

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
	movq	24+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 24+\O
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	32+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 32+\O
	movq	40+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 40+\O
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	48+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 48+\O
	movq	56+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 56+\O
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

.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S
.if \RDC != 1
	SQRN	\A, 0(%rdi), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.else
	SQRN	\A, \S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
	FP_RDCN_LOW	\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P, \T0, \T1, %rdx, %rsi
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, C
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P
.endif

	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \P
.endif

	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T1
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	xorq	\Z6, \Z6
	movq	56+\A, %rdx
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T1
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\Z7, \Z7
	movq	64+\A, %rdx
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T1
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	xorq	\Z8, \Z8
	movq	72+\A, %rdx
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z9, %rdx, \T1
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
	FINALC	\Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T1, %rdx, %rcx, 0(\T0)
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, C
	movq	80+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z10
	sbbq	$0, \Z0

	movq	8+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \B
	movq	88+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	movq	16+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \B
	movq	96+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	movq	24+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	104+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	movq	32+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	112+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	movq	40+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	120+\A, %rdx
	MULSUB	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z5, \Z5
	btq		$63, \Z4
	sbbq	$0, \Z5

	movq	48+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
	movq	128+\A, %rdx
	MULSUB	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T1
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	xorq	\Z6, \Z6
	btq		$63, \Z5
	sbbq	$0, \Z6

	movq	56+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
	movq	136+\A, %rdx
	MULSUB	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T1
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	xorq	\Z7, \Z7
	btq		$63, \Z6
	sbbq	$0, \Z7

	movq	64+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
	movq	144+\A, %rdx
	MULSUB	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T1
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif
	xorq	\Z8, \Z8
	btq		$63, \Z7
	sbbq	$0, \Z8

	movq	72+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
	movq	152+\A, %rdx
	MULSUB	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, 80+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z9, %rdx, \T1
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif
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
	FINALC	\Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T1, %rdx, %rcx, 0(\T0)
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, C
	movq	80+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	xorq	\T1, \T1
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P
.endif

	xorq	\Z0, \Z0
	movq	8+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, 80+\B
	movq	88+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z1, %rdx, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \P
.endif

	xorq	\Z1, \Z1
	movq	16+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, 80+\B
	movq	96+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z2, %rdx, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\Z2, \Z2
	movq	24+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, 80+\B
	movq	104+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z3, %rdx, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\Z3, \Z3
	movq	32+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 80+\B
	movq	112+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z4, %rdx, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\Z4, \Z4
	movq	40+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 80+\B
	movq	120+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z5, %rdx, \T1
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\Z5, \Z5
	movq	48+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 80+\B
	movq	128+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z6, %rdx, \T1
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	xorq	\Z6, \Z6
	movq	56+\A, %rdx
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 80+\B
	movq	136+\A, %rdx
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z7, %rdx, \T1
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\Z7, \Z7
	movq	64+\A, %rdx
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 80+\B
	movq	144+\A, %rdx
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z8, %rdx, \T1
	MULADD	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	xorq	\Z8, \Z8
	movq	72+\A, %rdx
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, 80+\B
	movq	152+\A, %rdx
	MULADD	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	movq	$U0, %rdx
	mulx	\Z9, %rdx, \T1
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
	FINALC	\Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T1, %rdx, %rcx, 0(\T0)
.endif
.endm

.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, 0, 8+\S
	MULM	\A, 80+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, 0, 0+\S
.else
	movq	%rcx, 16+\S
	leaq	24+\S, %rdx
	movq	%rdx, 0+\S
	MULM	\A, 80+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, 1, 0+\S
	movq	16+\S, %rcx
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, 1, 8+\S
	movq	8+\S, \T0
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

.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, RDC, S
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
	movq	\Z0, \Z10
	addq	80+\A, \Z10
	movq	\Z10, 0+\S
	movq	\Z1, \Z10
	adcq	88+\A, \Z10
	movq	\Z10, 8+\S
	movq	\Z2, \Z10
	adcq	96+\A, \Z10
	movq	\Z10, 16+\S
	movq	\Z3, \Z10
	adcq	104+\A, \Z10
	movq	\Z10, 24+\S
	movq	\Z4, \Z10
	adcq	112+\A, \Z10
	movq	\Z10, 32+\S
	movq	\Z5, \Z10
	adcq	120+\A, \Z10
	movq	\Z10, 40+\S
	movq	\Z6, \Z10
	adcq	128+\A, \Z10
	movq	\Z10, 48+\S
	movq	\Z7, \Z10
	adcq	136+\A, \Z10
	movq	\Z10, 56+\S
	movq	\Z8, \Z10
	adcq	144+\A, \Z10
	movq	\Z10, 64+\S
	movq	\Z9, \Z10
	adcq	152+\A, \Z10
	movq	\Z10, 72+\S
	movq	\Z0, \Z10
	addq	\Z0, \Z10
	movq	\Z10, 160+\S
	movq	\Z1, \Z10
	adcq	\Z1, \Z10
	movq	\Z10, 168+\S
	movq	\Z2, \Z10
	adcq	\Z2, \Z10
	movq	\Z10, 176+\S
	movq	\Z3, \Z10
	adcq	\Z3, \Z10
	movq	\Z10, 184+\S
	movq	\Z4, \Z10
	adcq	\Z4, \Z10
	movq	\Z10, 192+\S
	movq	\Z5, \Z10
	adcq	\Z5, \Z10
	movq	\Z10, 200+\S
	movq	\Z6, \Z10
	adcq	\Z6, \Z10
	movq	\Z10, 208+\S
	movq	\Z7, \Z10
	adcq	\Z7, \Z10
	movq	\Z10, 216+\S
	movq	\Z8, \Z10
	adcq	\Z8, \Z10
	movq	\Z10, 224+\S
	movq	\Z9, \Z10
	adcq	\Z9, \Z10
	movq	\Z10, 232+\S
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
	movq	\Z0, 80+\S
	movq	\Z1, 88+\S
	movq	\Z2, 96+\S
	movq	\Z3, 104+\S
	movq	\Z4, 112+\S
	movq	\Z5, 120+\S
	movq	\Z6, 128+\S
	movq	\Z7, 136+\S
	movq	\Z8, 144+\S
	movq	\Z9, 152+\S

	MULM	160+\S, 80+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP_MUL_LOW	160+\S, 80+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, \RDC, 240+\S
	MULM	0+\S, 80+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0
	FP_MUL_LOW	0+\S, 80+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P, \RDC, 248+\S
.endm
