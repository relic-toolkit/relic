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
#define P10 0x3290395E476657BA
#define P11 0xFFFFFFE4FF400142
#define U0	0x471A9E12007FFFFF
#elif FP_PRIME == 766
/* KSS16-P766 */
#define P0	0xB955C8905EF99F8D
#define P1	0x7D1C278139EFCE97
#define P2	0xB72041F5E8174021
#define P3	0xBC0E3DEC45049335
#define P4	0xB2CBF189D4D4B3CB
#define P5	0x941663A5AAF69407
#define P6	0x74C81A64B9FAAE0C
#define P7	0xB691EBF6CC4A8A9B
#define P8	0x24FB15165CCAB927
#define P9	0x91D2481C864D19F7
#define P10 0xD1F39E5F37AEACB3
#define P11 0x3C410B7E6EC19106
#define U0	0xC18CA908C52344BB
#elif FP_PRIME == 765
/* AFG16-765 */
#define P0	0x0000000000000001
#define P1	0x00000000384F0100
#define P2	0x7D00000000000000
#define P3	0xFFFEE92F0199280F
#define P4	0xF10B013FFFFFFFFF
#define P5	0x4AC04FAC4912BADA
#define P6	0x6AC50E5A1A6AEAE4
#define P7	0xEE9C1E7F21BD9E92
#define P8	0x249F514A2A836FBF
#define P9	0x8866F5670199231B
#define P10	0xB2847B1232833CC3
#define P11	0x16FAB993B0C96754
#define U0	0xFFFFFFFFFFFFFFFF
/* FM16-765
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
#define P10 0xBC5664C6F237BCB4
#define P11 0x166A30BEAF4CE221
#define U0	0xD000EFC07FFFFFFF
*/
#endif

#if defined(__APPLE__)
#define cdecl(S) _PREFIX(,S)
#else
#define cdecl(S) S
#endif

.text

.macro ADD1 i, j
	movq	8*\i(%rsi), %r10
	adcq	$0, %r10
	movq	%r10, 8*\i(%rdi)
	.if \i - \j
		ADD1 "(\i + 1)", \j
	.endif
.endm

.macro ADDN i, j
	movq	8*\i(%rdx), %r11
	adcq	8*\i(%rsi), %r11
	movq	%r11, 8*\i(%rdi)
	.if \i - \j
		ADDN "(\i + 1)", \j
	.endif
.endm

.macro SUB1 i, j
	movq	8*\i(%rsi),%r10
	sbbq	$0, %r10
	movq	%r10,8*\i(%rdi)
	.if \i - \j
		SUB1 "(\i + 1)", \j
	.endif
.endm

.macro SUBN i, j
	movq	8*\i(%rsi), %r8
	sbbq	8*\i(%rdx), %r8
	movq	%r8, 8*\i(%rdi)
	.if \i - \j
		SUBN "(\i + 1)", \j
	.endif
.endm

.macro DBLN i, j
	movq	8*\i(%rsi), %r8
	adcq	%r8, %r8
	movq	%r8, 8*\i(%rdi)
	.if \i - \j
		DBLN "(\i + 1)", \j
	.endif
.endm

.macro MULN i, j, k, C, R0, R1, R2, A, B
	.if \j > \k
		movq	8*\i(\A), %rax
		mulq	8*\j(\B)
		addq	%rax    , \R0
		adcq	%rdx    , \R1
		adcq	$0      , \R2
		MULN	"(\i + 1)", "(\j - 1)", \k, \C, \R0, \R1, \R2, \A, \B
	.else
		movq	8*\i(\A), %rax
		mulq	8*\j(\B)
		addq	%rax    , \R0
		movq	\R0     , 8*(\i+\j)(\C)
		adcq	%rdx    , \R1
		adcq	$0      , \R2
	.endif
.endm

.macro FP_MULN_LOW C, R0, R1, R2, A, B
	movq 	0(\A),%rax
	mulq 	0(\B)
	movq 	%rax ,0(\C)
	movq 	%rdx ,\R0

	xorq 	\R1,\R1
	xorq 	\R2,\R2
	MULN 	0, 1, 0, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	0, 2, 0, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	0, 3, 0, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	0, 4, 0, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	0, 5, 0, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	0, 6, 0, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	0, 7, 0, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	0, 8, 0, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	0, 9, 0, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	0,10, 0, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	0,11, 0, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	1,11, 1, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	2,11, 2, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	3,11, 3, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	4,11, 4, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	5,11, 5, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	6,11, 6, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	7,11, 7, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	8,11, 8, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	9,11, 9, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	10,11,10, \C, \R2, \R0, \R1, \A, \B

	movq	88(\A),%rax
	mulq	88(\B)
	addq	%rax  ,\R0
	movq	\R0   ,176(\C)
	adcq	%rdx  ,\R1
	movq	\R1   ,184(\C)
.endm

.macro _RDCN0 i, j, k, R0, R1, R2 A, P
	movq	8*\i(\A), %rax
#if U0 == 0xFFFFFFFFFFFFFF
	.if \j != 2
		mulq	8*\j(\P)
		addq	%rax, \R0
		adcq	%rdx, \R1
		adcq	$0, \R2
	.endif
#else
	mulq	8*\j(\P)
	addq	%rax, \R0
	adcq	%rdx, \R1
	adcq	$0, \R2
#endif
	.if \j > 1
		_RDCN0 "(\i + 1)", "(\j - 1)", \k, \R0, \R1, \R2, \A, \P
	.else
#if U0 == 0xFFFFFFFFFFFFFFFF
		addq	8*\k(\A), \R0
		adcq	$0, \R1
		adcq	$0, \R2
		negq	\R0
		movq	\R0, 8*\k(\A)
		adcq	$0, \R1
		adcq	$0, \R2
#else
		addq	8*\k(\A), \R0
		adcq	$0, \R1
		adcq	$0, \R2
		movq	\R0, %rax
		mulq	%rcx
		movq	%rax, 8*\k(\A)
		mulq	0(\P)
		addq	%rax , \R0
		adcq	%rdx , \R1
		adcq	$0   , \R2
#endif
		xorq	\R0, \R0
	.endif
.endm

.macro RDCN0 i, j, R0, R1, R2, A, P
	_RDCN0	\i, \j, \j, \R0, \R1, \R2, \A, \P
.endm

.macro _RDCN1 i, j, k, l, R0, R1, R2 A, P
#if U0 == 0xFFFFFFFFFFFFFF
	.if \j != 2
		movq	8*\i(\A), %rax
		mulq	8*\j(\P)
		addq	%rax, \R0
		adcq	%rdx, \R1
		adcq	$0, \R2
	.endif
#else
	movq	8*\i(\A), %rax
	mulq	8*\j(\P)
	addq	%rax, \R0
	adcq	%rdx, \R1
	adcq	$0, \R2
#endif
	.if \j > \l
		_RDCN1 "(\i + 1)", "(\j - 1)", \k, \l, \R0, \R1, \R2, \A, \P
	.else
		addq	8*\k(\A), \R0
		adcq	$0, \R1
		adcq	$0, \R2
		movq	\R0, 8*\k(\A)
		xorq	\R0, \R0
	.endif
.endm

.macro RDCN1 i, j, R0, R1, R2, A, P
	_RDCN1	\i, \j, "(\i + \j)", \i, \R0, \R1, \R2, \A, \P
.endm

// r8, r9, r10, r11, r12, r13, r14, r15, rbp, rbx, rsp, //rsi, rdi, //rax, rcx, rdx
.macro FP_RDCN_LOW C, R0, R1, R2, A, P
	xorq	\R1, \R1
#if U0 == 0xFFFFFFFFFFFFFFFF
	movq	0(\A), \R0
	negq	\R0
	movq	\R0 , 0(\A)
	adcq	$0   , \R1
#else
	movq	$U0, %rcx

	movq	0(\A), \R0
	movq	\R0  , %rax
	mulq	%rcx
	movq	%rax , 0(\A)
	mulq	0(\P)
	addq	%rax , \R0
	adcq	%rdx , \R1
#endif
	xorq    \R2  , \R2
	xorq    \R0  , \R0
	RDCN0	0, 1, \R1, \R2, \R0, \A, \P
	RDCN0	0, 2, \R2, \R0, \R1, \A, \P
	RDCN0	0, 3, \R0, \R1, \R2, \A, \P
	RDCN0	0, 4, \R1, \R2, \R0, \A, \P
	RDCN0	0, 5, \R2, \R0, \R1, \A, \P
	RDCN0	0, 6, \R0, \R1, \R2, \A, \P
	RDCN0	0, 7, \R1, \R2, \R0, \A, \P
	RDCN0	0, 8, \R2, \R0, \R1, \A, \P
	RDCN0	0, 9, \R0, \R1, \R2, \A, \P
	RDCN0	0,10, \R1, \R2, \R0, \A, \P
	RDCN0	0,11, \R2, \R0, \R1, \A, \P
	RDCN1	1,11, \R0, \R1, \R2, \A, \P
	RDCN1	2,11, \R1, \R2, \R0, \A, \P
	RDCN1	3,11, \R2, \R0, \R1, \A, \P
	RDCN1	4,11, \R0, \R1, \R2, \A, \P
	RDCN1	5,11, \R1, \R2, \R0, \A, \P
	RDCN1	6,11, \R2, \R0, \R1, \A, \P
	RDCN1	7,11, \R0, \R1, \R2, \A, \P
	RDCN1	8,11, \R1, \R2, \R0, \A, \P
	RDCN1	9,11, \R2, \R0, \R1, \A, \P
	RDCN1	10,11,\R0, \R1, \R2, \A, \P
	RDCN1	11,11,\R1, \R2, \R0, \A, \P
	addq	184(\A), \R2
	movq	\R2, 184(\A)
#if FP_PRIME == 768
	movq	$0, 192(\A)
	adcq	$0, 192(\A)
#endif

	movq	96(\A), %r11
	movq	104(\A), %r12
	movq	112(\A), %r13
	movq	120(\A), %r14
	movq	128(\A), %r15
	movq	136(\A), %rcx
	movq	144(\A), %rbp
	movq	152(\A), %rdx
	movq	160(\A), %r8
	movq	168(\A), %r9
	movq	176(\A), %r10
	movq	184(\A), %rax

	subq	p0(%rip), %r11
	sbbq	p1(%rip), %r12
	sbbq	p2(%rip), %r13
	sbbq	p3(%rip), %r14
	sbbq	p4(%rip), %r15
	sbbq	p5(%rip), %rcx
	sbbq	p6(%rip), %rbp
	sbbq	p7(%rip), %rdx
	sbbq	p8(%rip), %r8
	sbbq	p9(%rip), %r9
	sbbq	p10(%rip), %r10
	sbbq	p11(%rip), %rax
#if FP_PRIME == 768
	sbbq	$0, 192(\A)
#endif

	cmovc	96(\A), %r11
	cmovc	104(\A), %r12
	cmovc	112(\A), %r13
	cmovc	120(\A), %r14
	cmovc	128(\A), %r15
	cmovc	136(\A), %rcx
	cmovc	144(\A), %rbp
	cmovc	152(\A), %rdx
	cmovc	160(\A), %r8
	cmovc	168(\A), %r9
	cmovc	176(\A), %r10
	cmovc	184(\A), %rax
	movq	%r11,0(\C)
	movq	%r12,8(\C)
	movq	%r13,16(\C)
	movq	%r14,24(\C)
	movq	%r15,32(\C)
	movq	%rcx,40(\C)
	movq	%rbp,48(\C)
	movq	%rdx,56(\C)
	movq	%r8,64(\C)
	movq	%r9,72(\C)
	movq	%r10,80(\C)
	movq	%rax,88(\C)
.endm
