/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
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
	subq	$304, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
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
	movq	64(%rsi), %rbx
	movq	72(%rsi), %rbp
	movq	%r8, 160(%rsp)
	movq	%r9, 168(%rsp)
	movq	%r10, 176(%rsp)
	movq	%r11, 184(%rsp)
	movq	%r12, 192(%rsp)
	movq	%r13, 200(%rsp)
	movq	%r14, 208(%rsp)
	movq	%r15, 216(%rsp)
	movq	%rbx, 224(%rsp)
	movq	%rbp, 232(%rsp)
	movq	80(%rsi), %r8
	movq	88(%rsi), %r9
	movq	96(%rsi), %r10
	movq	104(%rsi), %r11
	movq	112(%rsi), %r12
	movq	120(%rsi), %r13
	movq	128(%rsi), %r14
	movq	136(%rsi), %r15
	movq	%r8, 240(%rsp)
	movq	%r9, 248(%rsp)
	movq	%r10, 256(%rsp)
	movq	%r11, 264(%rsp)
	movq	%r12, 272(%rsp)
	movq	%r13, 280(%rsp)
	movq	%r14, 288(%rsp)
	movq	%r15, 296(%rsp)

	FP2_MUL_LOW	160(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0, 0(%rsp)

	addq	$304, %rsp
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
	subq	$304, %rsp

	movq	%rdx, %rcx
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
	movq	%r8, 160(%rsp)
	movq	%r9, 168(%rsp)
	movq	%r10, 176(%rsp)
	movq	%r11, 184(%rsp)
	movq	%r12, 192(%rsp)
	movq	%r13, 200(%rsp)
	movq	%r14, 208(%rsp)
	movq	%r15, 216(%rsp)
	movq	%rbx, 224(%rsp)
	movq	%rbp, 232(%rsp)
	movq	80(%rsi), %r8
	movq	88(%rsi), %r9
	movq	96(%rsi), %r10
	movq	104(%rsi), %r11
	movq	112(%rsi), %r12
	movq	120(%rsi), %r13
	movq	128(%rsi), %r14
	movq	136(%rsi), %r15
	movq	%r8, 240(%rsp)
	movq	%r9, 248(%rsp)
	movq	%r10, 256(%rsp)
	movq	%r11, 264(%rsp)
	movq	%r12, 272(%rsp)
	movq	%r13, 280(%rsp)
	movq	%r14, 288(%rsp)
	movq	%r15, 296(%rsp)

	FP2_MUL_LOW	160(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 1, 0(%rsp)

	addq	$304, %rsp
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
	subq	$592, %rsp

	movq	%rdi, 16(%rsp)
	leaq	304(%rsp), %rdi
	leaq	448(%rsp), %rax
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
	movq	64(%rsi), %rbx
	movq	72(%rsi), %rbp
	movq	%r8, 160(%rsp)
	movq	%r9, 168(%rsp)
	movq	%r10, 176(%rsp)
	movq	%r11, 184(%rsp)
	movq	%r12, 192(%rsp)
	movq	%r13, 200(%rsp)
	movq	%r14, 208(%rsp)
	movq	%r15, 216(%rsp)
	movq	%rbx, 224(%rsp)
	movq	%rbp, 232(%rsp)
	movq	80(%rsi), %r8
	movq	88(%rsi), %r9
	movq	96(%rsi), %r10
	movq	104(%rsi), %r11
	movq	112(%rsi), %r12
	movq	120(%rsi), %r13
	movq	128(%rsi), %r14
	movq	136(%rsi), %r15
	movq	%r8, 240(%rsp)
	movq	%r9, 248(%rsp)
	movq	%r10, 256(%rsp)
	movq	%r11, 264(%rsp)
	movq	%r12, 272(%rsp)
	movq	%r13, 280(%rsp)
	movq	%r14, 288(%rsp)
	movq	%r15, 296(%rsp)

	FP2_MUL_LOW	160(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0, 0(%rsp)

	movq	16(%rsp), %rdi
	FP_RDCN_LOW	304(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, %rbx, p0(%rip), %r15, %rbx, %rdx, %rsi, %rbp
	movq	16(%rsp), %rdi
	addq	$72, %rdi
	FP_RDCN_LOW	448(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, %rbx, p0(%rip), %r15, %rbx, %rdx, %rsi, %rbp

	addq	$592, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif
