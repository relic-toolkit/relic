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
	subq	$40, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 0, 0(%rsp)

	addq	$40, %rsp
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
	subq	$40, %rsp

	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 1, 0(%rsp)

	addq	$40, %rsp
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#else

cdecl(fp2_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	subq	$168, %rsp

	movq	%rdi, 8(%rsp)
	leaq	40(%rsp), %rdi
	leaq	104(%rsp), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 0, 0(%rsp)

	movq	8(%rsp), %rdi
	FP_RDCN_LOW	40(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, p0(%rip), %rax, %rcx, %rdx, %rsi
	movq	8(%rsp), %rdi
	addq	$32, %rdi
	FP_RDCN_LOW	104(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, p0(%rip), %rax, %rcx, %rdx, %rsi

	addq	$168, %rsp
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif
