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
	subq	$48, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, p0(%rip), 0, 0(%rsp)

	addq	$48, %rsp
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
	subq	$48, %rsp

	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, p0(%rip), 1, 0(%rsp)

	addq	$48, %rsp
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
	subq	$208, %rsp

	movq	%rdi, 8(%rsp)
	leaq	48(%rsp), %rdi
	leaq	128(%rsp), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, p0(%rip), 0, 0(%rsp)

	movq	8(%rsp), %rdi
	FP_RDCN_LOW	48(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, p0(%rip), %rcx, %r12, %rdx, %rsi, %r13
	movq	8(%rsp), %rdi
	addq	$40, %rdi
	FP_RDCN_LOW	128(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, p0(%rip), %rcx, %r12, %rdx, %rsi, %r13

	addq	$208, %rsp
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif

#ifdef FP2_NORD_ASM

.macro NORD i j
	movq	8*\i(%rsi), %r8
	movq	RLC_DV_STRIDE+8*\i(%rsi), %r9
	leaq	(%r10,%r8,2), %rax
	shrxq	%rcx, %r8, %r10
	leaq	(%r11,%r9,2), %rdx
	shrxq	%rcx, %r9, %r11
	notq	%r9
	adcx	%r9, %rax
	adox	%r8, %rdx
	movq	%rax, 8*\i(%rdi)
	movq	%rdx, RLC_DV_STRIDE+8*\i(%rdi)
	.if \i - \j
		NORD "(\i + 1)" \j
	.endif
.endm

.global cdecl(fp2_nord_low)

cdecl(fp2_nord_low):
	push	%r12
	push	%r13
	push	%r14

	movq	$63, %rcx
	xorl	%r10d, %r10d
	xorl	%r11d, %r11d
	stc
	NORD	0 9

	sbbq	%rcx, %rcx
	notq	%rcx
	testq	%rcx, %rcx
	movq	40(%rdi), %r8
	movq	48(%rdi), %r9
	movq	56(%rdi), %r10
	movq	64(%rdi), %r11
	movq	72(%rdi), %rax
	movq	$0, %rdx
	cmovs	p0(%rip), %rdx
	adcx	%rdx, %r8
	movq	$0, %rsi
	cmovs	p1(%rip), %rsi
	adcx	%rsi, %r9
	movq	$0, %rdx
	cmovs	p2(%rip), %rdx
	adcx	%rdx, %r10
	movq	$0, %rsi
	cmovs	p3(%rip), %rsi
	adcx	%rsi, %r11
	movq	$0, %rdx
	cmovs	p4(%rip), %rdx
	adcx	%rdx, %rax
	FINALC	%r8, %r9, %r10, %r11, %rax, %rdx, %rsi, %r12, %r13, %r14, 40(%rdi)

	movq	RLC_DV_STRIDE+40(%rdi), %r8
	movq	RLC_DV_STRIDE+48(%rdi), %r9
	movq	RLC_DV_STRIDE+56(%rdi), %r10
	movq	RLC_DV_STRIDE+64(%rdi), %r11
	movq	RLC_DV_STRIDE+72(%rdi), %rax
	FINALC	%r8, %r9, %r10, %r11, %rax, %rdx, %rsi, %r12, %r13, %r14, RLC_DV_STRIDE+40(%rdi)
	FINALC	%rdx, %rsi, %r12, %r13, %r14, %r8, %r9, %r10, %r11, %rax, RLC_DV_STRIDE+40(%rdi)

	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif
