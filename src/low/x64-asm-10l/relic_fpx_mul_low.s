/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of the low-level quadratic extension field multiplication.
 *
 * @ingroup fpx
 */

#include "relic_fp_low.h"
#include "macro.s"

.text

#ifdef FP2_ASM

.global cdecl(fp2_muln_low)

cdecl(fp2_muln_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$264, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 0(%rsp)
	movq	%rdi, 8(%rsp)
	movq	%rdx, %rcx
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
	movq	80(%rsi), %rbp
	movq	%r8, 104(%rsp)
	movq	%r9, 112(%rsp)
	movq	%r10, 120(%rsp)
	movq	%r11, 128(%rsp)
	movq	%r12, 136(%rsp)
	movq	%r13, 144(%rsp)
	movq	%r14, 152(%rsp)
	movq	%r15, 160(%rsp)
	movq	%rax, 168(%rsp)
	movq	%rbx, 176(%rsp)
	movq	%rbp, 184(%rsp)
	movq	88(%rsi), %r8
	movq	96(%rsi), %r9
	movq	104(%rsi), %r10
	movq	112(%rsi), %r11
	movq	120(%rsi), %r12
	movq	128(%rsi), %r13
	movq	136(%rsi), %r14
	movq	144(%rsi), %r15
	movq	152(%rsi), %rax
	movq	%r8, 192(%rsp)
	movq	%r9, 200(%rsp)
	movq	%r10, 208(%rsp)
	movq	%r11, 216(%rsp)
	movq	%r12, 224(%rsp)
	movq	%r13, 232(%rsp)
	movq	%r14, 240(%rsp)
	movq	%r15, 248(%rsp)
	movq	%rax, 256(%rsp)

	FP2_MUL_LOW	104(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	addq	$264, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

.global cdecl(fp2_mulm_low)

#ifdef FP2_MUL_RDC

cdecl(fp2_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$264, %rsp

	movq	%rdi, 8(%rsp)
	movq	%rdx, %rcx
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
	movq	80(%rsi), %rbp
	movq	%r8, 104(%rsp)
	movq	%r9, 112(%rsp)
	movq	%r10, 120(%rsp)
	movq	%r11, 128(%rsp)
	movq	%r12, 136(%rsp)
	movq	%r13, 144(%rsp)
	movq	%r14, 152(%rsp)
	movq	%r15, 160(%rsp)
	movq	%rax, 168(%rsp)
	movq	%rbx, 176(%rsp)
	movq	%rbp, 184(%rsp)
	movq	88(%rsi), %r8
	movq	96(%rsi), %r9
	movq	104(%rsi), %r10
	movq	112(%rsi), %r11
	movq	120(%rsi), %r12
	movq	128(%rsi), %r13
	movq	136(%rsi), %r14
	movq	144(%rsi), %r15
	movq	152(%rsi), %rax
	movq	%r8, 192(%rsp)
	movq	%r9, 200(%rsp)
	movq	%r10, 208(%rsp)
	movq	%r11, 216(%rsp)
	movq	%r12, 224(%rsp)
	movq	%r13, 232(%rsp)
	movq	%r14, 240(%rsp)
	movq	%r15, 248(%rsp)
	movq	%rax, 256(%rsp)

	FP2_MUL_LOW	104(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1, 0(%rsp)

	addq	$264, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#else

cdecl(fp2_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$584, %rsp

	movq	%rdi, 24(%rsp)
	leaq	264(%rsp), %rax
	movq	%rax, 8(%rsp)
	leaq	424(%rsp), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx
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
	movq	80(%rsi), %rbp
	movq	%r8, 104(%rsp)
	movq	%r9, 112(%rsp)
	movq	%r10, 120(%rsp)
	movq	%r11, 128(%rsp)
	movq	%r12, 136(%rsp)
	movq	%r13, 144(%rsp)
	movq	%r14, 152(%rsp)
	movq	%r15, 160(%rsp)
	movq	%rax, 168(%rsp)
	movq	%rbx, 176(%rsp)
	movq	%rbp, 184(%rsp)
	movq	88(%rsi), %r8
	movq	96(%rsi), %r9
	movq	104(%rsi), %r10
	movq	112(%rsi), %r11
	movq	120(%rsi), %r12
	movq	128(%rsi), %r13
	movq	136(%rsi), %r14
	movq	144(%rsi), %r15
	movq	152(%rsi), %rax
	movq	%r8, 192(%rsp)
	movq	%r9, 200(%rsp)
	movq	%r10, 208(%rsp)
	movq	%r11, 216(%rsp)
	movq	%r12, 224(%rsp)
	movq	%r13, 232(%rsp)
	movq	%r14, 240(%rsp)
	movq	%r15, 248(%rsp)
	movq	%rax, 256(%rsp)

	FP2_MUL_LOW	104(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	movq	24(%rsp), %rdi
	FP_RDCN_LOW	264(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, %rbx, %rbp, p0(%rip), %rbx, %rbp, %rdx, %rsi
	movq	24(%rsp), %rdi
	addq	$80, %rdi
	FP_RDCN_LOW	424(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, %rbx, %rbp, p0(%rip), %rbx, %rbp, %rdx, %rsi

	addq	$584, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif
