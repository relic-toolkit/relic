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
	subq	$64, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 0, 0(%rsp)

	addq	$64, %rsp
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
	subq	$64, %rsp

	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 1, 0(%rsp)

	addq	$64, %rsp
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
	subq	$256, %rsp

	movq	%rdi, 16(%rsp)
	leaq	64(%rsp), %rdi
	leaq	160(%rsp), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, p0(%rip), 0, 0(%rsp)

	movq	16(%rsp), %rdi
	FP_RDCN_LOW	64(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, p0(%rip), %r12, %r13, %rdx, %rsi, %r14, %r15
	movq	16(%rsp), %rdi
	addq	$48, %rdi
	FP_RDCN_LOW	160(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, p0(%rip), %r12, %r13, %rdx, %rsi, %r14, %r15

	addq	$256, %rsp
	pop		%rbx
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
	push	%r15
	push	%rbx

	movq	$63, %rcx
	xorl	%r10d, %r10d
	xorl	%r11d, %r11d
	stc
	NORD	0 11

	sbbq	%rcx, %rcx
	notq	%rcx
	testq	%rcx, %rcx
	movq	48(%rdi), %r8
	movq	56(%rdi), %r9
	movq	64(%rdi), %r10
	movq	72(%rdi), %r11
	movq	80(%rdi), %rax
	movq	88(%rdi), %rdx
	movq	$0, %rsi
	cmovs	p0(%rip), %rsi
	adcx	%rsi, %r8
	movq	$0, %r12
	cmovs	p1(%rip), %r12
	adcx	%r12, %r9
	movq	$0, %rsi
	cmovs	p2(%rip), %rsi
	adcx	%rsi, %r10
	movq	$0, %r12
	cmovs	p3(%rip), %r12
	adcx	%r12, %r11
	movq	$0, %rsi
	cmovs	p4(%rip), %rsi
	adcx	%rsi, %rax
	movq	$0, %r12
	cmovs	p5(%rip), %r12
	adcx	%r12, %rdx
	FINALC	%r8, %r9, %r10, %r11, %rax, %rdx, %rsi, %r12, %r13, %r14, %r15, %rbx, 48(%rdi)

	movq	RLC_DV_STRIDE+48(%rdi), %r8
	movq	RLC_DV_STRIDE+56(%rdi), %r9
	movq	RLC_DV_STRIDE+64(%rdi), %r10
	movq	RLC_DV_STRIDE+72(%rdi), %r11
	movq	RLC_DV_STRIDE+80(%rdi), %rax
	movq	RLC_DV_STRIDE+88(%rdi), %rdx
	FINALC	%r8, %r9, %r10, %r11, %rax, %rdx, %rsi, %r12, %r13, %r14, %r15, %rbx, RLC_DV_STRIDE+48(%rdi)
	FINALC	%rsi, %r12, %r13, %r14, %r15, %rbx, %r8, %r9, %r10, %r11, %rax, %rdx, RLC_DV_STRIDE+48(%rdi)

	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif
