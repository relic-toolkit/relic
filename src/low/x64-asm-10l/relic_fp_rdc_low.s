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

/**
 * @file
 *
 * Implementation of low-level prime field modular reduction.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"

#include "macro.s"

.text

.global cdecl(fp_rdcn_low)

/*
 * Function: fp_rdcn_low
 * Inputs: rdi = c, rsi = a
 *
 * The lower half of a is reduced first, giving (a_l + m x p) / 2^640 <= p,
 * and the upper half is added at the end, so a is never written and no carry
 * register is needed. This takes a < p x 2^640, as usual.
 * Registers: z in r8-r15, rax, rbx, rbp; T0 = rcx, T1 = rdi; 0(%rsp) = c.
 */
cdecl(fp_rdcn_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	push	%rdi

	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rax
	movq	72(%rsi), %rbx
	xorq	%rbp, %rbp

	movq	$U0, %rdx
	mulx	%r8, %rdx, %rcx
	MULADD	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%r9, %rdx, %rcx
	MULADD	%r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %r8, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%r10, %rdx, %rcx
	MULADD	%r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %r8, %r9, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%r11, %rdx, %rcx
	MULADD	%r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %r8, %r9, %r10, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%r12, %rdx, %rcx
	MULADD	%r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %r8, %r9, %r10, %r11, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%r13, %rdx, %rcx
	MULADD	%r13, %r14, %r15, %rax, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%r14, %rdx, %rcx
	MULADD	%r14, %r15, %rax, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%r15, %rdx, %rcx
	MULADD	%r15, %rax, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%rax, %rdx, %rcx
	MULADD	%rax, %rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rcx, %rdi, p0(%rip)

	movq	$U0, %rdx
	mulx	%rbx, %rdx, %rcx
	MULADD	%rbx, %rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rcx, %rdi, p0(%rip)

	// Add the upper half of a, which leaves z < 2p.
	addq	80(%rsi), %rbp
	adcq	88(%rsi), %r8
	adcq	96(%rsi), %r9
	adcq	104(%rsi), %r10
	adcq	112(%rsi), %r11
	adcq	120(%rsi), %r12
	adcq	128(%rsi), %r13
	adcq	136(%rsi), %r14
	adcq	144(%rsi), %r15
	adcq	152(%rsi), %rax

	movq	0(%rsp), %rsi
	FINALC	%rbp, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, 0(%rsi)

	pop		%rdi
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
