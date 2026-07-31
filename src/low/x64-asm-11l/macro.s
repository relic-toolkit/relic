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
#define P10 0x000000009401FF90
#define U0	0x3DDEBD583B76B01D
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
	MULN	1,10, 1, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	2,10, 2, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	3,10, 3, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	4,10, 4, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	5,10, 5, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	6,10, 6, \C, \R0, \R1, \R2, \A, \B
	xorq 	\R0,\R0
	MULN	7,10, 7, \C, \R1, \R2, \R0, \A, \B
	xorq 	\R1,\R1
	MULN	8,10, 8, \C, \R2, \R0, \R1, \A, \B
	xorq 	\R2,\R2
	MULN	9,10, 9, \C, \R0, \R1, \R2, \A, \B

	movq	80(\A),%rax
	mulq	80(\B)
	addq	%rax  ,\R1
	movq	\R1   ,160(\C)
	adcq	%rdx  ,\R2
	movq	\R2   ,168(\C)
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
	RDCN1	1,10, \R2, \R0, \R1, \A, \P
	RDCN1	2,10, \R0, \R1, \R2, \A, \P
	RDCN1	3,10, \R1, \R2, \R0, \A, \P
	RDCN1	4,10, \R2, \R0, \R1, \A, \P
	RDCN1	5,10, \R0, \R1, \R2, \A, \P
	RDCN1	6,10, \R1, \R2, \R0, \A, \P
	RDCN1	7,10, \R2, \R0, \R1, \A, \P
	RDCN1	8,10, \R0, \R1, \R2, \A, \P
	RDCN1	9,10, \R1, \R2, \R0, \A, \P
	RDCN1	10,10, \R2, \R0, \R1, \A, \P
	addq	168(\A), \R0
	movq	\R0, 168(\A)

	movq	88(\A), %r11
	movq	96(\A), %r12
	movq	104(\A), %r13
	movq	112(\A), %r14
	movq	120(\A), %r15
	movq	128(\A), %rcx
	movq	136(\A), %rbp
	movq	144(\A), %rdx
	movq	152(\A), %r8
	movq	160(\A), %r9
	movq	168(\A), %r10

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

	cmovc	88(\A), %r11
	cmovc	96(\A), %r12
	cmovc	104(\A), %r13
	cmovc	112(\A), %r14
	cmovc	120(\A), %r15
	cmovc	128(\A), %rcx
	cmovc	136(\A), %rbp
	cmovc	144(\A), %rdx
	cmovc	152(\A), %r8
	cmovc	160(\A), %r9
	cmovc	168(\A), %r10
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
.endm
