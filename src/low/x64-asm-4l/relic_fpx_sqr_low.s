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
	subq	$112, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 96(%rsp)

	FP2_SQR_LOW	0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 0, 0(%rsp)

	addq	$112, %rsp
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#ifdef FP2_SQR_RDC

cdecl(fp2_sqrm_low):
	push	%r12
	push	%r13
	push	%r14
	subq	$112, %rsp

	FP2_SQR_LOW	0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 1, 0(%rsp)

	addq	$112, %rsp
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#else

cdecl(fp2_sqrm_low):
	push	%r12
	push	%r13
	push	%r14
	subq	$248, %rsp

	movq	%rdi, 112(%rsp)
	leaq	120(%rsp), %rdi
	leaq	184(%rsp), %rax
	movq	%rax, 96(%rsp)

	FP2_SQR_LOW	0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, p0(%rip), 0, 0(%rsp)

	movq	112(%rsp), %rdi
	FP_RDCN_LOW	120(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, p0(%rip), %rax, %rcx, %rdx, %rsi
	movq	112(%rsp), %rdi
	addq	$32, %rdi
	FP_RDCN_LOW	184(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, p0(%rip), %rax, %rcx, %rdx, %rsi

	addq	$248, %rsp
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif
