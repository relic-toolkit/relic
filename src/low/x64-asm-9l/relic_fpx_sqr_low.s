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
	subq	$232, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 216(%rsp)
	movq	%rsi, %rcx

	FP2_SQR_LOW	0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0, 0(%rsp)

	addq	$232, %rsp
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
	subq	$232, %rsp

	movq	%rsi, %rcx

	FP2_SQR_LOW	0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 1, 0(%rsp)

	addq	$232, %rsp
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
	subq	$528, %rsp

	movq	%rdi, 232(%rsp)
	leaq	240(%rsp), %rdi
	leaq	384(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	%rsi, %rcx

	FP2_SQR_LOW	0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0, 0(%rsp)

	movq	232(%rsp), %rdi
	FP_RDCN_LOW	240(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, %rbx, p0(%rip), %r15, %rbx, %rdx, %rsi, %rbp
	movq	232(%rsp), %rdi
	addq	$72, %rdi
	FP_RDCN_LOW	384(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, %rbx, p0(%rip), %r15, %rbx, %rdx, %rsi, %rbp

	addq	$528, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif
