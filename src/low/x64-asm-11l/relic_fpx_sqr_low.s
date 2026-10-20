/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Implementation of the low-level quadratic extension field squaring.
 *
 * @ingroup fpx
 */

#include "relic_fp_low.h"
#include "macro.s"

.text

#ifdef FP2_ASM

.global cdecl(fp2_sqrn_low)
.global cdecl(fp2_sqrm_low)

cdecl(fp2_sqrn_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$456, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 264(%rsp)
	movq	%rdi, 272(%rsp)
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
	movq	88(%rsi), %rcx
	movq	%r8, 280(%rsp)
	movq	%r9, 288(%rsp)
	movq	%r10, 296(%rsp)
	movq	%r11, 304(%rsp)
	movq	%r12, 312(%rsp)
	movq	%r13, 320(%rsp)
	movq	%r14, 328(%rsp)
	movq	%r15, 336(%rsp)
	movq	%rax, 344(%rsp)
	movq	%rbx, 352(%rsp)
	movq	%rbp, 360(%rsp)
	movq	%rcx, 368(%rsp)
	movq	96(%rsi), %r8
	movq	104(%rsi), %r9
	movq	112(%rsi), %r10
	movq	120(%rsi), %r11
	movq	128(%rsi), %r12
	movq	136(%rsi), %r13
	movq	144(%rsi), %r14
	movq	152(%rsi), %r15
	movq	160(%rsi), %rax
	movq	168(%rsi), %rbx
	movq	%r8, 376(%rsp)
	movq	%r9, 384(%rsp)
	movq	%r10, 392(%rsp)
	movq	%r11, 400(%rsp)
	movq	%r12, 408(%rsp)
	movq	%r13, 416(%rsp)
	movq	%r14, 424(%rsp)
	movq	%r15, 432(%rsp)
	movq	%rax, 440(%rsp)
	movq	%rbx, 448(%rsp)

	FP2_SQR_LOW	280(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	addq	$456, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#ifdef FP2_SQR_RDC

cdecl(fp2_sqrm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$456, %rsp

	leaq	88(%rdi), %rax
	movq	%rax, 264(%rsp)
	movq	%rdi, 272(%rsp)
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
	movq	88(%rsi), %rcx
	movq	%r8, 280(%rsp)
	movq	%r9, 288(%rsp)
	movq	%r10, 296(%rsp)
	movq	%r11, 304(%rsp)
	movq	%r12, 312(%rsp)
	movq	%r13, 320(%rsp)
	movq	%r14, 328(%rsp)
	movq	%r15, 336(%rsp)
	movq	%rax, 344(%rsp)
	movq	%rbx, 352(%rsp)
	movq	%rbp, 360(%rsp)
	movq	%rcx, 368(%rsp)
	movq	96(%rsi), %r8
	movq	104(%rsi), %r9
	movq	112(%rsi), %r10
	movq	120(%rsi), %r11
	movq	128(%rsi), %r12
	movq	136(%rsi), %r13
	movq	144(%rsi), %r14
	movq	152(%rsi), %r15
	movq	160(%rsi), %rax
	movq	168(%rsi), %rbx
	movq	%r8, 376(%rsp)
	movq	%r9, 384(%rsp)
	movq	%r10, 392(%rsp)
	movq	%r11, 400(%rsp)
	movq	%r12, 408(%rsp)
	movq	%r13, 416(%rsp)
	movq	%r14, 424(%rsp)
	movq	%r15, 432(%rsp)
	movq	%rax, 440(%rsp)
	movq	%rbx, 448(%rsp)

	FP2_SQR_LOW	280(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rsi, %rdi, p0(%rip), 1, 0(%rsp)

	addq	$456, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#else

cdecl(fp2_sqrm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$816, %rsp

	movq	%rdi, 456(%rsp)
	leaq	464(%rsp), %rax
	movq	%rax, 272(%rsp)
	leaq	640(%rsp), %rax
	movq	%rax, 264(%rsp)
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
	movq	88(%rsi), %rcx
	movq	%r8, 280(%rsp)
	movq	%r9, 288(%rsp)
	movq	%r10, 296(%rsp)
	movq	%r11, 304(%rsp)
	movq	%r12, 312(%rsp)
	movq	%r13, 320(%rsp)
	movq	%r14, 328(%rsp)
	movq	%r15, 336(%rsp)
	movq	%rax, 344(%rsp)
	movq	%rbx, 352(%rsp)
	movq	%rbp, 360(%rsp)
	movq	%rcx, 368(%rsp)
	movq	96(%rsi), %r8
	movq	104(%rsi), %r9
	movq	112(%rsi), %r10
	movq	120(%rsi), %r11
	movq	128(%rsi), %r12
	movq	136(%rsi), %r13
	movq	144(%rsi), %r14
	movq	152(%rsi), %r15
	movq	160(%rsi), %rax
	movq	168(%rsi), %rbx
	movq	%r8, 376(%rsp)
	movq	%r9, 384(%rsp)
	movq	%r10, 392(%rsp)
	movq	%r11, 400(%rsp)
	movq	%r12, 408(%rsp)
	movq	%r13, 416(%rsp)
	movq	%r14, 424(%rsp)
	movq	%r15, 432(%rsp)
	movq	%rax, 440(%rsp)
	movq	%rbx, 448(%rsp)

	FP2_SQR_LOW	280(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rsi, %rdi, p0(%rip), 0, 0(%rsp)

	FP_RDCN_LOW	464(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, %rbx, %rbp, %rdi, p0(%rip), %rdi, %rdx, %rsi, 456(%rsp)
	movq	456(%rsp), %rdi
	addq	$88, %rdi
	movq	%rdi, 456(%rsp)
	FP_RDCN_LOW	640(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, %rbx, %rbp, %rdi, p0(%rip), %rdi, %rdx, %rsi, 456(%rsp)

	addq	$816, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif
