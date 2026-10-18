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

#if FP_PRIME == 672
#define P0	0xAAAAAAAAB69E6DCB
#define P1	0xAAAAAAAD47EDE1A6
#define P2	0x155555CD7FA7A5F8
#define P3	0x31555CF4F24050ED
#define P4	0x7A0067B8303EEB4B
#define P5	0xC20AB5B9A7CDA7F2
#define P6	0x43EC9CFE1549FD59
#define P7	0x9A7991563C5E468D
#define P8	0xBF9E0FEFD5921162
#define P9	0xF28BFFB0C610FB10
#define P10	0x000000009401FF90
#define U0	0x3DDEBD583B76B01D
#define BAR	0xDD64CB651AE50CA8
#define BARS	31
#define BARJ	10
#else
#error "x64-asm-11l supports only FP_PRIME = 672."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

#if P10 < 0x4000000000000000
#define FP2_MUL_RDC
#endif

#if P10 < 0x5555555555555555
#define FP2_SQR_RDC
#endif

#if defined(FP_QNRES) && RLC_ALLOC == RLC_AUTO
#define FP2_ASM
#endif

#if defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif

#if defined(__APPLE__)
.section __TEXT,__const
#else
.section .rodata
#endif
.p2align 3
ones:	.quad	-1

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

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12
	movq	0+\A, %rdx
	mulx	0+\B, \Z0, \Z1
	mulx	8+\B, \Z12, \Z2
	addq	\Z12, \Z1
	mulx	16+\B, \Z12, \Z3
	adcq	\Z12, \Z2
	mulx	24+\B, \Z12, \Z4
	adcq	\Z12, \Z3
	mulx	32+\B, \Z12, \Z5
	adcq	\Z12, \Z4
	mulx	40+\B, \Z12, \Z6
	adcq	\Z12, \Z5
	mulx	48+\B, \Z12, \Z7
	adcq	\Z12, \Z6
	mulx	56+\B, \Z12, \Z8
	adcq	\Z12, \Z7
	mulx	64+\B, \Z12, \Z9
	adcq	\Z12, \Z8
	mulx	72+\B, \Z12, \Z10
	adcq	\Z12, \Z9
	mulx	80+\B, \Z12, \Z11
	adcq	\Z12, \Z10
	adcq	$0, \Z11
.endm

.macro MULADD Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, M
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
	mulx	80+\M, \T1, \T0
	adcx	\T1, \Z10
	adox	\T0, \Z11
	movq	$0, \T1
	adcx	\T1, \Z11
.endm

.macro MULADD1 Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, X, T, ZR, M
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
	adox	\ZR, \X
	adcx	\ZR, \X
.endm

.macro MULRDC1 Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T, ZR, P
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T
	mulx	0+\P, \T, \T
	adcx	ones(%rip), \Z0
	adox	\T, \Z1
	mulx	8+\P, \T, \Z0
	adcx	\T, \Z1
	adox	\Z0, \Z2
	mulx	16+\P, \T, \Z0
	adcx	\T, \Z2
	adox	\Z0, \Z3
	mulx	24+\P, \T, \Z0
	adcx	\T, \Z3
	adox	\Z0, \Z4
	mulx	32+\P, \T, \Z0
	adcx	\T, \Z4
	adox	\Z0, \Z5
	mulx	40+\P, \T, \Z0
	adcx	\T, \Z5
	adox	\Z0, \Z6
	mulx	48+\P, \T, \Z0
	adcx	\T, \Z6
	adox	\Z0, \Z7
	mulx	56+\P, \T, \Z0
	adcx	\T, \Z7
	adox	\Z0, \Z8
	mulx	64+\P, \T, \Z0
	adcx	\T, \Z8
	adox	\Z0, \Z9
	mulx	72+\P, \T, \Z0
	adcx	\T, \Z9
	adox	\Z0, \Z10
	mulx	80+\P, \T, \Z0
	adcx	\T, \Z10
	adox	\Z0, \Z11
	adcx	\ZR, \Z11
.endm

.macro MULSUB Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, M
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
	sbbq	$0, \Z11
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
	mulx	80+\M, \T1, \T0
	sbbq	\T1, \Z10
	sbbq	\T0, \Z11
.endm

.macro FINALC V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, C0, C1, C2, D
	movq	\V0, 0+\D
	movq	\V1, 8+\D
	movq	\V2, 16+\D
	movq	\V3, 24+\D
	movq	\V4, 32+\D
	movq	\V5, 40+\D
	movq	\V6, 48+\D
	movq	\V7, 56+\D
	movq	\V8, \C0
	movq	\V9, \C1
	movq	\V10, \C2
	subq	p0(%rip), \V0
	sbbq	p1(%rip), \V1
	sbbq	p2(%rip), \V2
	sbbq	p3(%rip), \V3
	sbbq	p4(%rip), \V4
	sbbq	p5(%rip), \V5
	sbbq	p6(%rip), \V6
	sbbq	p7(%rip), \V7
	sbbq	p8(%rip), \C0
	sbbq	p9(%rip), \C1
	sbbq	p10(%rip), \C2
	cmovc	0+\D, \V0
	cmovc	8+\D, \V1
	cmovc	16+\D, \V2
	cmovc	24+\D, \V3
	cmovc	32+\D, \V4
	cmovc	40+\D, \V5
	cmovc	48+\D, \V6
	cmovc	56+\D, \V7
	cmovc	\V8, \C0
	cmovc	\V9, \C1
	cmovc	\V10, \C2
	movq	\V0, 0+\D
	movq	\V1, 8+\D
	movq	\V2, 16+\D
	movq	\V3, 24+\D
	movq	\V4, 32+\D
	movq	\V5, 40+\D
	movq	\V6, 48+\D
	movq	\V7, 56+\D
	movq	\C0, 64+\D
	movq	\C1, 72+\D
	movq	\C2, 80+\D
.endm

.macro RDCSTEP Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P
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
	adox	\T1, \Z10
	mulx	80+\P, \T0, \T1
	adcx	\T0, \Z10
	adox	\T1, \Z0
	adcq	$0, \Z0
.endm

.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \T0, \T1, \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \T0, \T1, \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \T0, \T1, \P
	RDCSTEP	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
	RDCSTEP	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
	RDCSTEP	\Z6, \Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
	RDCSTEP	\Z7, \Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
	RDCSTEP	\Z8, \Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
	RDCSTEP	\Z9, \Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
	RDCSTEP	\Z10, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endm

.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, H0, H1, H2, H3, H4, H5, H6, H7, H8, H9, H10
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
	adcq	\H10, \Z10
.endm

.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, T0, T1, P, C0, C1, C2, CP
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
	movq	80+\A, \Z10
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, \T1, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, 88+\A, 96+\A, 104+\A, 112+\A, 120+\A, 128+\A, 136+\A, 144+\A, 152+\A, 160+\A, 168+\A
	movq	\CP, \T0
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \C0, \C1, \C2, 0(\T0)
.endm

.macro SQRN A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1
	movq	0+\A, %rdx
	mulx	8+\A, \Z0, \Z1
	movq	\Z0, 8+\O
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
	mulx	80+\A, \T0, \Z0
	adcq	\T0, \Z9
	adcq	$0, \Z0
	movq	\Z1, 16+\O

	movq	8+\A, %rdx
	xorq	\Z1, \Z1
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
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	adcq	$0, \Z1
	movq	\Z2, 24+\O
	movq	\Z3, 32+\O

	movq	16+\A, %rdx
	xorq	\Z2, \Z2
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
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	adcq	$0, \Z2
	movq	\Z4, 40+\O
	movq	\Z5, 48+\O

	movq	24+\A, %rdx
	xorq	\Z3, \Z3
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
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	adcq	$0, \Z3
	movq	\Z6, 56+\O
	movq	\Z7, 64+\O

	movq	32+\A, %rdx
	xorq	\Z4, \Z4
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
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	adcq	$0, \Z4
	movq	\Z8, 72+\O
	movq	\Z9, 80+\O

	movq	40+\A, %rdx
	xorq	\Z5, \Z5
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
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	adcq	$0, \Z5

	movq	48+\A, %rdx
	xorq	\Z6, \Z6
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	adcq	$0, \Z6

	movq	56+\A, %rdx
	xorq	\Z7, \Z7
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	adcq	$0, \Z7

	movq	64+\A, %rdx
	xorq	\Z8, \Z8
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	adcq	$0, \Z8

	movq	72+\A, %rdx
	mulx	80+\A, \T0, \Z9
	addq	\T0, \Z8
	adcq	$0, \Z9

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
	movq	72+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 72+\O
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	80+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 80+\O
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
	adcx	\Z8, \Z8
	adox	\T1, \Z8
	movq	\Z8, 152+\O
	movq	80+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z9, \Z9
	adox	\T0, \Z9
	movq	\Z9, 160+\O
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 168+\O
.endm

.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S, C
.if \RDC != 1
	SQRN	\A, 0(%rdi), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.else
	SQRN	\A, \S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
	FP_RDCN_LOW	\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, %rsi, \P, %rsi, %rdx, %rdi, \C
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, P, RDC, C
	xorq	\T1, \T1
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	8+\A, %rdx
	MULADD1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	MULRDC1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	16+\A, %rdx
	MULADD1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	MULRDC1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	24+\A, %rdx
	MULADD1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	MULRDC1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	32+\A, %rdx
	MULADD1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	MULRDC1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	40+\A, %rdx
	MULADD1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	MULRDC1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	48+\A, %rdx
	MULADD1	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	MULRDC1	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	56+\A, %rdx
	MULADD1	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	MULRDC1	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	64+\A, %rdx
	MULADD1	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	MULRDC1	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	72+\A, %rdx
	MULADD1	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	MULRDC1	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	80+\A, %rdx
	MULADD1	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z10, 80(\T0)
.else
	MULRDC1	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\C, \T0
	movq	\Z11, 88(\T0)
	movq	\Z0, 96(\T0)
	movq	\Z1, 104(\T0)
	movq	\Z2, 112(\T0)
	movq	\Z3, 120(\T0)
	movq	\Z4, 128(\T0)
	movq	\Z5, 136(\T0)
	movq	\Z6, 144(\T0)
	movq	\Z7, 152(\T0)
	movq	\Z8, 160(\T0)
	movq	\Z9, 168(\T0)
.else
	movq	\C, \T0
	FINALC	\Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T1, %rdx, 0(\T0)
.endif
.endm

.macro FP2_MUL0_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, P, RDC, C
	movq	88+\A, %rdx
	MULSUB	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P
.endif
	xorq	\Z0, \Z0
	btq		$63, \Z11
	sbbq	$0, \Z0

	movq	8+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, \T1, \B
	movq	96+\A, %rdx
	MULSUB	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, \T1, \P
.endif
	xorq	\Z1, \Z1
	btq		$63, \Z0
	sbbq	$0, \Z1

	movq	16+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, \T1, \B
	movq	104+\A, %rdx
	MULSUB	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, \T1, \P
.endif
	xorq	\Z2, \Z2
	btq		$63, \Z1
	sbbq	$0, \Z2

	movq	24+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, \T1, \B
	movq	112+\A, %rdx
	MULSUB	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif
	xorq	\Z3, \Z3
	btq		$63, \Z2
	sbbq	$0, \Z3

	movq	32+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
	movq	120+\A, %rdx
	MULSUB	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif
	xorq	\Z4, \Z4
	btq		$63, \Z3
	sbbq	$0, \Z4

	movq	40+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
	movq	128+\A, %rdx
	MULSUB	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif
	xorq	\Z5, \Z5
	btq		$63, \Z4
	sbbq	$0, \Z5

	movq	48+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
	movq	136+\A, %rdx
	MULSUB	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif
	xorq	\Z6, \Z6
	btq		$63, \Z5
	sbbq	$0, \Z6

	movq	56+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
	movq	144+\A, %rdx
	MULSUB	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif
	xorq	\Z7, \Z7
	btq		$63, \Z6
	sbbq	$0, \Z7

	movq	64+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
	movq	152+\A, %rdx
	MULSUB	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif
	xorq	\Z8, \Z8
	btq		$63, \Z7
	sbbq	$0, \Z8

	movq	72+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
	movq	160+\A, %rdx
	MULSUB	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif
	xorq	\Z9, \Z9
	btq		$63, \Z8
	sbbq	$0, \Z9

	movq	80+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B
	movq	168+\A, %rdx
	MULSUB	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, 88+\B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z10, 80(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif
	testq	\Z9, \Z9

	movq	$0, \T0
	cmovs	p0(%rip), \T0
	adcx	\T0, \Z11
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
	movq	$0, \T0
	cmovs	p10(%rip), \T0
	adcx	\T0, \Z9
.if \RDC != 1
	movq	\C, \T0
	movq	\Z11, 88(\T0)
	movq	\Z0, 96(\T0)
	movq	\Z1, 104(\T0)
	movq	\Z2, 112(\T0)
	movq	\Z3, 120(\T0)
	movq	\Z4, 128(\T0)
	movq	\Z5, 136(\T0)
	movq	\Z6, 144(\T0)
	movq	\Z7, 152(\T0)
	movq	\Z8, 160(\T0)
	movq	\Z9, 168(\T0)
.else
	movq	\C, \T0
	FINALC	\Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T1, %rdx, 0(\T0)
.endif
.endm

.macro FP2_MUL1_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, P, RDC, C
	movq	88+\A, %rdx
	xorq	\T1, \T1
	MULADD	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	xorq	\T1, \T1
	MULRDC1	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	8+\A, %rdx
	MULADD1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, \T1, 88+\B
	movq	96+\A, %rdx
	MULADD	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	MULRDC1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	16+\A, %rdx
	MULADD1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, \T1, 88+\B
	movq	104+\A, %rdx
	MULADD	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	MULRDC1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	24+\A, %rdx
	MULADD1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, \T1, 88+\B
	movq	112+\A, %rdx
	MULADD	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	MULRDC1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	32+\A, %rdx
	MULADD1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, \T1, 88+\B
	movq	120+\A, %rdx
	MULADD	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	MULRDC1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	40+\A, %rdx
	MULADD1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, 88+\B
	movq	128+\A, %rdx
	MULADD	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	MULRDC1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	48+\A, %rdx
	MULADD1	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, 88+\B
	movq	136+\A, %rdx
	MULADD	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	MULRDC1	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	56+\A, %rdx
	MULADD1	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, 88+\B
	movq	144+\A, %rdx
	MULADD	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	MULRDC1	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	64+\A, %rdx
	MULADD1	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, 88+\B
	movq	152+\A, %rdx
	MULADD	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	MULRDC1	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	72+\A, %rdx
	MULADD1	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, 88+\B
	movq	160+\A, %rdx
	MULADD	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	MULRDC1	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, \T1, \P
.endif

	xorq	\T0, \T0
	movq	80+\A, %rdx
	MULADD1	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, 88+\B
	movq	168+\A, %rdx
	MULADD	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \B
.if \RDC != 1
	movq	\C, \T0
	movq	\Z10, 80(\T0)
.else
	MULRDC1	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, \P
.endif

.if \RDC != 1
	movq	\C, \T0
	movq	\Z11, 88(\T0)
	movq	\Z0, 96(\T0)
	movq	\Z1, 104(\T0)
	movq	\Z2, 112(\T0)
	movq	\Z3, 120(\T0)
	movq	\Z4, 128(\T0)
	movq	\Z5, 136(\T0)
	movq	\Z6, 144(\T0)
	movq	\Z7, 152(\T0)
	movq	\Z8, 160(\T0)
	movq	\Z9, 168(\T0)
.else
	movq	\C, \T0
	FINALC	\Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T1, %rdx, 0(\T0)
.endif
.endm

.macro FP2_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, P, RDC, S
.if \RDC != 1
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P, 0, 8+\S
	MULM	\A, 88+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P, 0, 0+\S
.else
	leaq	16+\S, %rdx
	movq	%rdx, 0+\S
	MULM	\A, 88+\B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0
	FP2_MUL1_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P, 1, 0+\S
	MULM	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0
	FP2_MUL0_LOW	\A, \B, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P, 1, 8+\S
	movq	8+\S, \T0
	movq	16+\S, \Z0
	movq	24+\S, \Z1
	movq	32+\S, \Z2
	movq	40+\S, \Z3
	movq	48+\S, \Z4
	movq	56+\S, \Z5
	movq	64+\S, \Z6
	movq	72+\S, \Z7
	movq	80+\S, \Z8
	movq	88+\S, \Z9
	movq	96+\S, \Z10
	movq	\Z0, 88(\T0)
	movq	\Z1, 96(\T0)
	movq	\Z2, 104(\T0)
	movq	\Z3, 112(\T0)
	movq	\Z4, 120(\T0)
	movq	\Z5, 128(\T0)
	movq	\Z6, 136(\T0)
	movq	\Z7, 144(\T0)
	movq	\Z8, 152(\T0)
	movq	\Z9, 160(\T0)
	movq	\Z10, 168(\T0)
.endif
.endm

.macro FP2_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, T1, P, RDC, S
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
	movq	80+\A, \Z10
	movq	\Z0, \Z11
	addq	88+\A, \Z11
	movq	\Z11, 0+\S
	movq	\Z1, \Z11
	adcq	96+\A, \Z11
	movq	\Z11, 8+\S
	movq	\Z2, \Z11
	adcq	104+\A, \Z11
	movq	\Z11, 16+\S
	movq	\Z3, \Z11
	adcq	112+\A, \Z11
	movq	\Z11, 24+\S
	movq	\Z4, \Z11
	adcq	120+\A, \Z11
	movq	\Z11, 32+\S
	movq	\Z5, \Z11
	adcq	128+\A, \Z11
	movq	\Z11, 40+\S
	movq	\Z6, \Z11
	adcq	136+\A, \Z11
	movq	\Z11, 48+\S
	movq	\Z7, \Z11
	adcq	144+\A, \Z11
	movq	\Z11, 56+\S
	movq	\Z8, \Z11
	adcq	152+\A, \Z11
	movq	\Z11, 64+\S
	movq	\Z9, \Z11
	adcq	160+\A, \Z11
	movq	\Z11, 72+\S
	movq	\Z10, \Z11
	adcq	168+\A, \Z11
	movq	\Z11, 80+\S
	movq	\Z0, \Z11
	addq	\Z0, \Z11
	movq	\Z11, 176+\S
	movq	\Z1, \Z11
	adcq	\Z1, \Z11
	movq	\Z11, 184+\S
	movq	\Z2, \Z11
	adcq	\Z2, \Z11
	movq	\Z11, 192+\S
	movq	\Z3, \Z11
	adcq	\Z3, \Z11
	movq	\Z11, 200+\S
	movq	\Z4, \Z11
	adcq	\Z4, \Z11
	movq	\Z11, 208+\S
	movq	\Z5, \Z11
	adcq	\Z5, \Z11
	movq	\Z11, 216+\S
	movq	\Z6, \Z11
	adcq	\Z6, \Z11
	movq	\Z11, 224+\S
	movq	\Z7, \Z11
	adcq	\Z7, \Z11
	movq	\Z11, 232+\S
	movq	\Z8, \Z11
	adcq	\Z8, \Z11
	movq	\Z11, 240+\S
	movq	\Z9, \Z11
	adcq	\Z9, \Z11
	movq	\Z11, 248+\S
	movq	\Z10, \Z11
	adcq	\Z10, \Z11
	movq	\Z11, 256+\S
	subq	88+\A, \Z0
	sbbq	96+\A, \Z1
	sbbq	104+\A, \Z2
	sbbq	112+\A, \Z3
	sbbq	120+\A, \Z4
	sbbq	128+\A, \Z5
	sbbq	136+\A, \Z6
	sbbq	144+\A, \Z7
	sbbq	152+\A, \Z8
	sbbq	160+\A, \Z9
	sbbq	168+\A, \Z10
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
	adcq	80+\P, \Z10
	movq	\Z0, 88+\S
	movq	\Z1, 96+\S
	movq	\Z2, 104+\S
	movq	\Z3, 112+\S
	movq	\Z4, 120+\S
	movq	\Z5, 128+\S
	movq	\Z6, 136+\S
	movq	\Z7, 144+\S
	movq	\Z8, 152+\S
	movq	\Z9, 160+\S
	movq	\Z10, 168+\S

	MULM	176+\S, 88+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0
	FP_MUL_LOW	176+\S, 88+\A, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P, \RDC, 264+\S
	MULM	0+\S, 88+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0
	FP_MUL_LOW	0+\S, 88+\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \T1, \P, \RDC, 272+\S
.endm
