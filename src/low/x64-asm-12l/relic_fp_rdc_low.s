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
 * Computes (a mod 2^768 + q x p) / 2^768 + floor(a / 2^768) for a < pR, which
 * is below 2p. The first term stays below 2^768 at each step, so no carry
 * leaves the 13-word accumulator.
 */
cdecl(fp_rdcn_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$FRAME, %rsp

	movq	%rdi, CPTR
	movq	$0, ZERO
	movq	$-1, ONES
	xorq	%rdi, %rdi
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	movq	64(%rsi), %rbx
	movq	72(%rsi), %rbp
	movq	80(%rsi), %rax
	movq	88(%rsi), %rcx
	MULRDC	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rcx, , %rdi, p0(%rip)
	MULRDC	%r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rcx, %r8, , %rdi, p0(%rip)
	MULRDC	%r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rcx, %r8, %r9, , %rdi, p0(%rip)
	MULRDC	%r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rcx, %r8, %r9, %r10, , %rdi, p0(%rip)
	MULRDC	%r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rcx, %r8, %r9, %r10, %r11, , %rdi, p0(%rip)
	MULRDC	%r13, %r14, %r15, %rbx, %rbp, %rax, %rcx, %r8, %r9, %r10, %r11, %r12, , %rdi, p0(%rip)
	MULRDC	%r14, %r15, %rbx, %rbp, %rax, %rcx, %r8, %r9, %r10, %r11, %r12, %r13, , %rdi, p0(%rip)
	MULRDC	%r15, %rbx, %rbp, %rax, %rcx, %r8, %r9, %r10, %r11, %r12, %r13, %r14, , %rdi, p0(%rip)
	MULRDC	%rbx, %rbp, %rax, %rcx, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, , %rdi, p0(%rip)
	MULRDC	%rbp, %rax, %rcx, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, , %rdi, p0(%rip)
	MULRDC	%rax, %rcx, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, , %rdi, p0(%rip)
	MULRDC	%rcx, %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, , %rdi, p0(%rip)

	addq	96(%rsi), %r8
	adcq	104(%rsi), %r9
	adcq	112(%rsi), %r10
	adcq	120(%rsi), %r11
	adcq	128(%rsi), %r12
	adcq	136(%rsi), %r13
	adcq	144(%rsi), %r14
	adcq	152(%rsi), %r15
	adcq	160(%rsi), %rbx
	adcq	168(%rsi), %rbp
	adcq	176(%rsi), %rax
	adcq	184(%rsi), %rcx
#if FP_PRIME == 768
	movq	$0, %rdi
	adcq	$0, %rdi
	FINALC	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rcx, %rdi
#else
	FINALC	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, %rcx
#endif

	addq	$FRAME, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
