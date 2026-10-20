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
 * Implementation of the low-level prime field multiplication functions.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

.text

.global cdecl(fp_mul1_low)
.global cdecl(fp_muln_low)
.global cdecl(fp_mulm_low)

cdecl(fp_mul1_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$8, %rsp

	movq	%rdi, 0(%rsp)
	mulxq	0(%rsi), %r8, %rax
	mulxq	8(%rsi), %r9, %rbx
	addq	%rax, %r9
	mulxq	16(%rsi), %r10, %rax
	adcq	%rbx, %r10
	mulxq	24(%rsi), %r11, %rbx
	adcq	%rax, %r11
	mulxq	32(%rsi), %rcx, %rax
	adcq	%rbx, %rcx
	mulxq	40(%rsi), %rdi, %rbx
	adcq	%rax, %rdi
	mulxq	48(%rsi), %r12, %rax
	adcq	%rbx, %r12
	mulxq	56(%rsi), %r13, %rbx
	adcq	%rax, %r13
	mulxq	64(%rsi), %r14, %r15
	adcq	%rbx, %r14
	adcq	$0, %r15

	movq	%r14, %rax
	shrdq	$BARS, %r15, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	xorq	%rax, %rax
	stc
	mulxq	p0(%rip), %rax, %rbx
	notq	%rax
	adcx	%rax, %r8
	mulxq	p1(%rip), %rax, %rsi
	adox	%rbx, %rax
	notq	%rax
	adcx	%rax, %r9
	mulxq	p2(%rip), %rax, %rbx
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r10
	mulxq	p3(%rip), %rax, %rsi
	adox	%rbx, %rax
	notq	%rax
	adcx	%rax, %r11
	mulxq	p4(%rip), %rax, %rbx
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %rcx
	mulxq	p5(%rip), %rax, %rsi
	adox	%rbx, %rax
	notq	%rax
	adcx	%rax, %rdi
	mulxq	p6(%rip), %rax, %rbx
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r12
	mulxq	p7(%rip), %rax, %rsi
	adox	%rbx, %rax
	notq	%rax
	adcx	%rax, %r13
	mulxq	p8(%rip), %rax, %rbx
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r14
	movq	0(%rsp), %r15

	.rept 2
	movq	%r8, 0(%r15)
	subq	p0(%rip), %r8
	movq	%r9, 8(%r15)
	sbbq	p1(%rip), %r9
	movq	%r10, 16(%r15)
	sbbq	p2(%rip), %r10
	movq	%r11, 24(%r15)
	sbbq	p3(%rip), %r11
	movq	%rcx, %rbp
	sbbq	p4(%rip), %rbp
	movq	%rdi, %rbx
	sbbq	p5(%rip), %rbx
	movq	%r12, %rsi
	sbbq	p6(%rip), %rsi
	movq	%r13, %rdx
	sbbq	p7(%rip), %rdx
	movq	%r14, %rax
	sbbq	p8(%rip), %rax
	cmovc	0(%r15), %r8
	cmovc	8(%r15), %r9
	cmovc	16(%r15), %r10
	cmovc	24(%r15), %r11
	cmovnc	%rbp, %rcx
	cmovnc	%rbx, %rdi
	cmovnc	%rsi, %r12
	cmovnc	%rdx, %r13
	cmovnc	%rax, %r14
	.endr

	movq	%r8, 0(%r15)
	movq	%r9, 8(%r15)
	movq	%r10, 16(%r15)
	movq	%r11, 24(%r15)
	movq	%rcx, 32(%r15)
	movq	%rdi, 40(%r15)
	movq	%r12, 48(%r15)
	movq	%r13, 56(%r15)
	movq	%r14, 64(%r15)

	addq	$8, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_muln_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$72, %rsp

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
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rbx, 64(%rsp)

	MULM	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP_MUL_LOW	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 0

	addq	$72, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_mulm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp
	subq	$72, %rsp

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
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rbx, 64(%rsp)

	MULM	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi
	FP_MUL_LOW	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rsi, %rax, p0(%rip), 1

	addq	$72, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
