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
 * Implementation of the low-level quadratic extension field squaring.
 *
 * @ingroup fpx
 */

#include "relic_fp_low.h"
#include "macro.s"

.text

#if defined(FP2_ASM) && defined(FP_QNRES)

.global cdecl(fp2_sqrn_low)
.global cdecl(fp2_sqrm_low)

cdecl(fp2_sqrn_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$208, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 192(%rsp)

	FP2_SQR_LOW	0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 0, 0(%rsp)

	addq	$208, %rsp
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
	subq	$208, %rsp

	FP2_SQR_LOW	0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 1, 0(%rsp)

	addq	$208, %rsp
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
	subq	$472, %rsp

	movq	%rdi, 208(%rsp)
	leaq	216(%rsp), %rdi
	leaq	344(%rsp), %rax
	movq	%rax, 192(%rsp)

	FP2_SQR_LOW	0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 0, 0(%rsp)

	movq	208(%rsp), %rdi
	FP_RDCN_LOW	216(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, p0(%rip), %r14, %r15, %rdx, %rsi, %rbx, %rbp
	movq	208(%rsp), %rdi
	addq	$64, %rdi
	FP_RDCN_LOW	344(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, p0(%rip), %r14, %r15, %rdx, %rsi, %rbx, %rbp

	addq	$472, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif

#if defined(FP2_ASM) && !defined(FP_QNRES)

.global cdecl(fp2_sqrn_low)
.global cdecl(fp2_sqrm_low)

cdecl(fp2_sqrn_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$144, %rsp

	movq	%rdi, 0(%rsp)
	movq	%rsi, 8(%rsp)
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	addq	%r8, %r8
	adcq	%r9, %r9
	adcq	%r10, %r10
	adcq	%r11, %r11
	adcq	%r12, %r12
	adcq	%r13, %r13
	adcq	%r14, %r14
	adcq	%r15, %r15
	movq	%r8, 16(%rsp)
	movq	%r9, 24(%rsp)
	movq	%r10, 32(%rsp)
	movq	%r11, 40(%rsp)
	movq	%r12, 48(%rsp)
	movq	%r13, 56(%rsp)
	movq	%r14, 64(%rsp)
	movq	%r15, 72(%rsp)
	movq	$FP2_QNR, %rdx
	mulx	64(%rsi), %r8, %r9
	mulx	72(%rsi), %rbp, %r10
	addq	%rbp, %r9
	mulx	80(%rsi), %rbp, %r11
	adcq	%rbp, %r10
	mulx	88(%rsi), %rbp, %r12
	adcq	%rbp, %r11
	mulx	96(%rsi), %rbp, %r13
	adcq	%rbp, %r12
	mulx	104(%rsi), %rbp, %r14
	adcq	%rbp, %r13
	mulx	112(%rsi), %rbp, %r15
	adcq	%rbp, %r14
	mulx	120(%rsi), %rbp, %rbx
	adcq	%rbp, %r15
	movq	%r8, 80(%rsp)
	movq	%r9, 88(%rsp)
	movq	%r10, 96(%rsp)
	movq	%r11, 104(%rsp)
	movq	%r12, 112(%rsp)
	movq	%r13, 120(%rsp)
	movq	%r14, 128(%rsp)
	movq	%r15, 136(%rsp)

	MULM	0(%rsi), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp
	FP2_MUL0_LOW	0(%rsi), 0(%rsi), 80(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 0

	movq	0(%rsp), %rdi
	movq	8(%rsp), %rsi
	leaq	RLC_DV_STRIDE(%rdi), %rdi
	MULM	16(%rsp), 64(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp
	FP_MUL_LOW	16(%rsp), 64(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 0

	addq	$144, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp2_sqrm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$144, %rsp

	movq	%rdi, 0(%rsp)
	movq	%rsi, 8(%rsp)
	movq	0(%rsi), %r8
	movq	8(%rsi), %r9
	movq	16(%rsi), %r10
	movq	24(%rsi), %r11
	movq	32(%rsi), %r12
	movq	40(%rsi), %r13
	movq	48(%rsi), %r14
	movq	56(%rsi), %r15
	addq	%r8, %r8
	adcq	%r9, %r9
	adcq	%r10, %r10
	adcq	%r11, %r11
	adcq	%r12, %r12
	adcq	%r13, %r13
	adcq	%r14, %r14
	adcq	%r15, %r15
	movq	%r8, 16(%rsp)
	movq	%r9, 24(%rsp)
	movq	%r10, 32(%rsp)
	movq	%r11, 40(%rsp)
	movq	%r12, 48(%rsp)
	movq	%r13, 56(%rsp)
	movq	%r14, 64(%rsp)
	movq	%r15, 72(%rsp)
	movq	$FP2_QNR, %rdx
	mulx	64(%rsi), %r8, %r9
	mulx	72(%rsi), %rbp, %r10
	addq	%rbp, %r9
	mulx	80(%rsi), %rbp, %r11
	adcq	%rbp, %r10
	mulx	88(%rsi), %rbp, %r12
	adcq	%rbp, %r11
	mulx	96(%rsi), %rbp, %r13
	adcq	%rbp, %r12
	mulx	104(%rsi), %rbp, %r14
	adcq	%rbp, %r13
	mulx	112(%rsi), %rbp, %r15
	adcq	%rbp, %r14
	mulx	120(%rsi), %rbp, %rbx
	adcq	%rbp, %r15
	movq	%r8, 80(%rsp)
	movq	%r9, 88(%rsp)
	movq	%r10, 96(%rsp)
	movq	%r11, 104(%rsp)
	movq	%r12, 112(%rsp)
	movq	%r13, 120(%rsp)
	movq	%r14, 128(%rsp)
	movq	%r15, 136(%rsp)

	MULM	0(%rsi), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp
	FP2_MUL0_LOW	0(%rsi), 0(%rsi), 80(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 1

	movq	0(%rsp), %rdi
	movq	8(%rsp), %rsi
	leaq	64(%rdi), %rdi
	MULM	16(%rsp), 64(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp
	FP_MUL_LOW	16(%rsp), 64(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 1

	addq	$144, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif
