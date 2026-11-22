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
	subq	$152, %rsp

	leaq	RLC_DV_STRIDE(%rdi), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 0, 0(%rsp)

	addq	$152, %rsp
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
	subq	$152, %rsp

	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 1, 0(%rsp)

	addq	$152, %rsp
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
	subq	$408, %rsp

	movq	%rdi, 24(%rsp)
	leaq	152(%rsp), %rdi
	leaq	280(%rsp), %rax
	movq	%rax, 0(%rsp)
	movq	%rdx, %rcx

	FP2_MUL_LOW	0(%rcx), 0(%rsi), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 0, 0(%rsp)

	movq	24(%rsp), %rdi
	FP_RDCN_LOW	152(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, p0(%rip), %r14, %r15, %rdx, %rsi, %rbx, %rbp
	movq	24(%rsp), %rdi
	addq	$64, %rdi
	FP_RDCN_LOW	280(%rsp), %r8, %r9, %r10, %r11, %rax, %rcx, %r12, %r13, %r14, %r15, p0(%rip), %r14, %r15, %rdx, %rsi, %rbx, %rbp

	addq	$408, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif

#endif

#ifdef FP2_NORD_ASM

.global cdecl(fp2_nord_low)

cdecl(fp2_nord_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$64, %rsp

	movq	$QNR, %rdx
	mulx	RLC_DV_STRIDE+0(%rsi), %rax, %rbx
	movq	%rax, 0(%rsp)
	mulx	RLC_DV_STRIDE+8(%rsi), %rax, %rbp
	addq	%rbx, %rax
	movq	%rax, 8(%rsp)
	mulx	RLC_DV_STRIDE+16(%rsi), %rax, %rbx
	adcq	%rbp, %rax
	movq	%rax, 16(%rsp)
	mulx	RLC_DV_STRIDE+24(%rsi), %rax, %rbp
	adcq	%rbx, %rax
	movq	%rax, 24(%rsp)
	mulx	RLC_DV_STRIDE+32(%rsi), %rax, %rbx
	adcq	%rbp, %rax
	movq	%rax, 32(%rsp)
	mulx	RLC_DV_STRIDE+40(%rsi), %rax, %rbp
	adcq	%rbx, %rax
	movq	%rax, 40(%rsp)
	mulx	RLC_DV_STRIDE+48(%rsi), %rax, %rbx
	adcq	%rbp, %rax
	movq	%rax, 48(%rsp)
	mulx	RLC_DV_STRIDE+56(%rsi), %rax, %rbp
	adcq	%rbx, %rax
	movq	%rax, 56(%rsp)
	mulx	RLC_DV_STRIDE+64(%rsi), %r8, %rbx
	adcq	%rbp, %r8
	mulx	RLC_DV_STRIDE+72(%rsi), %r9, %rbp
	adcq	%rbx, %r9
	mulx	RLC_DV_STRIDE+80(%rsi), %r10, %rbx
	adcq	%rbp, %r10
	mulx	RLC_DV_STRIDE+88(%rsi), %r11, %rbp
	adcq	%rbx, %r11
	mulx	RLC_DV_STRIDE+96(%rsi), %r12, %rbx
	adcq	%rbp, %r12
	mulx	RLC_DV_STRIDE+104(%rsi), %r13, %rbp
	adcq	%rbx, %r13
	mulx	RLC_DV_STRIDE+112(%rsi), %r14, %rbx
	adcq	%rbp, %r14
	mulx	RLC_DV_STRIDE+120(%rsi), %r15, %rbp
	adcq	%rbx, %r15

	movq	0(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+0(%rdi)
	movq	8(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+8(%rdi)
	movq	16(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+16(%rdi)
	movq	24(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+24(%rdi)
	movq	32(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+32(%rdi)
	movq	40(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+40(%rdi)
	movq	48(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+48(%rdi)
	movq	56(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+56(%rdi)
	movq	64(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+64(%rdi)
	movq	72(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+72(%rdi)
	movq	80(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+80(%rdi)
	movq	88(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+88(%rdi)
	movq	96(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+96(%rdi)
	movq	104(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+104(%rdi)
	movq	112(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+112(%rdi)
	movq	120(%rsi), %rax
	movq	%rax, RLC_DV_STRIDE+120(%rdi)

	movq	%r15, %rax
	shrq	$BARS, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx
	xorq	%rax, %rax
	stc
	mulxq	p0(%rip), %rax, %rbx
	notq	%rax
	adcx	%rax, %r8
	mulxq	p1(%rip), %rax, %rbp
	adox	%rbx, %rax
	notq	%rax
	adcx	%rax, %r9
	mulxq	p2(%rip), %rax, %rbx
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r10
	mulxq	p3(%rip), %rax, %rbp
	adox	%rbx, %rax
	notq	%rax
	adcx	%rax, %r11
	mulxq	p4(%rip), %rax, %rbx
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r12
	mulxq	p5(%rip), %rax, %rbp
	adox	%rbx, %rax
	notq	%rax
	adcx	%rax, %r13
	mulxq	p6(%rip), %rax, %rbx
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r14
	mulxq	p7(%rip), %rax, %rbp
	adox	%rbx, %rax
	notq	%rax
	adcx	%rax, %r15
	FINALC	%r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rcx, %rdx, %rsi, %rbx, %rbp, 64(%rdi)
	FINALC	%r8, %r9, %rax, %rcx, %rdx, %rsi, %rbx, %rbp, %r10, %r11, %r12, %r13, %r14, %r15, 64(%rdi)

	movq	$0, %rax
	subq	0(%rsp), %rax
	movq	%rax, 0(%rdi)
	movq	$0, %rax
	sbbq	8(%rsp), %rax
	movq	%rax, 8(%rdi)
	movq	$0, %rax
	sbbq	16(%rsp), %rax
	movq	%rax, 16(%rdi)
	movq	$0, %rax
	sbbq	24(%rsp), %rax
	movq	%rax, 24(%rdi)
	movq	$0, %rax
	sbbq	32(%rsp), %rax
	movq	%rax, 32(%rdi)
	movq	$0, %rax
	sbbq	40(%rsp), %rax
	movq	%rax, 40(%rdi)
	movq	$0, %rax
	sbbq	48(%rsp), %rax
	movq	%rax, 48(%rdi)
	movq	$0, %rax
	sbbq	56(%rsp), %rax
	movq	%rax, 56(%rdi)
	movq	$0, %rax
	sbbq	%r8, %rax
	movq	%rax, %r8
	movq	$0, %rax
	sbbq	%r9, %rax
	movq	%rax, %r9
	movq	$0, %rax
	sbbq	%r10, %rax
	movq	%rax, %r10
	movq	$0, %rax
	sbbq	%r11, %rax
	movq	%rax, %r11
	movq	$0, %rax
	sbbq	%r12, %rax
	movq	%rax, %r12
	movq	$0, %rax
	sbbq	%r13, %rax
	movq	%rax, %r13
	movq	$0, %rax
	sbbq	%r14, %rax
	movq	%rax, %r14
	movq	$0, %rax
	sbbq	%r15, %rax
	movq	%rax, %r15
	sbbq	%rcx, %rcx
	testq	%rcx, %rcx
	movq	$0, %rax
	cmovs	p0(%rip), %rax
	adcx	%rax, %r8
	movq	%r8, 64(%rdi)
	movq	$0, %rdx
	cmovs	p1(%rip), %rdx
	adcx	%rdx, %r9
	movq	%r9, 72(%rdi)
	movq	$0, %rax
	cmovs	p2(%rip), %rax
	adcx	%rax, %r10
	movq	%r10, 80(%rdi)
	movq	$0, %rdx
	cmovs	p3(%rip), %rdx
	adcx	%rdx, %r11
	movq	%r11, 88(%rdi)
	movq	$0, %rax
	cmovs	p4(%rip), %rax
	adcx	%rax, %r12
	movq	%r12, 96(%rdi)
	movq	$0, %rdx
	cmovs	p5(%rip), %rdx
	adcx	%rdx, %r13
	movq	%r13, 104(%rdi)
	movq	$0, %rax
	cmovs	p6(%rip), %rax
	adcx	%rax, %r14
	movq	%r14, 112(%rdi)
	movq	$0, %rdx
	cmovs	p7(%rip), %rdx
	adcx	%rdx, %r15
	movq	%r15, 120(%rdi)

	addq	$64, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

#endif
