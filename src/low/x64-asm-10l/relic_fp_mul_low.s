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
 * Implementation of the low-level prime field multiplication functions.
 *
 * @ingroup bn
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
	mulxq	8(%rsi), %r9, %rbp
	addq	%rax, %r9
	mulxq	16(%rsi), %r10, %rax
	adcq	%rbp, %r10
	mulxq	24(%rsi), %r11, %rbp
	adcq	%rax, %r11
	mulxq	32(%rsi), %rcx, %rax
	adcq	%rbp, %rcx
	mulxq	40(%rsi), %rdi, %rbp
	adcq	%rax, %rdi
	mulxq	48(%rsi), %r12, %rax
	adcq	%rbp, %r12
	mulxq	56(%rsi), %r13, %rbp
	adcq	%rax, %r13
	mulxq	64(%rsi), %r14, %rax
	adcq	%rbp, %r14
	mulxq	72(%rsi), %r15, %rbx
	adcq	%rax, %r15
	adcq	$0, %rbx

	movq	%r15, %rax
	shrdq	$BARS, %rbx, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	xorq	%rax, %rax
	stc
	mulxq	p0(%rip), %rax, %rbp
	notq	%rax
	adcx	%rax, %r8
	mulxq	p1(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r9
	mulxq	p2(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r10
	mulxq	p3(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r11
	mulxq	p4(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %rcx
	mulxq	p5(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %rdi
	mulxq	p6(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r12
	mulxq	p7(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r13
	mulxq	p8(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r14
	mulxq	p9(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r15
	movq	0(%rsp), %rbx

	.rept 2
	movq	%r8, 0(%rbx)
	subq	p0(%rip), %r8
	movq	%r9, 8(%rbx)
	sbbq	p1(%rip), %r9
	movq	%r10, 16(%rbx)
	sbbq	p2(%rip), %r10
	movq	%r11, 24(%rbx)
	sbbq	p3(%rip), %r11
	movq	%rcx, 32(%rbx)
	sbbq	p4(%rip), %rcx
	movq	%rdi, 40(%rbx)
	sbbq	p5(%rip), %rdi
	movq	%r12, %rbp
	sbbq	p6(%rip), %rbp
	movq	%r13, %rsi
	sbbq	p7(%rip), %rsi
	movq	%r14, %rdx
	sbbq	p8(%rip), %rdx
	movq	%r15, %rax
	sbbq	p9(%rip), %rax
	cmovc	0(%rbx), %r8
	cmovc	8(%rbx), %r9
	cmovc	16(%rbx), %r10
	cmovc	24(%rbx), %r11
	cmovc	32(%rbx), %rcx
	cmovc	40(%rbx), %rdi
	cmovnc	%rbp, %r12
	cmovnc	%rsi, %r13
	cmovnc	%rdx, %r14
	cmovnc	%rax, %r15
	.endr

	movq	%r8, 0(%rbx)
	movq	%r9, 8(%rbx)
	movq	%r10, 16(%rbx)
	movq	%r11, 24(%rbx)
	movq	%rcx, 32(%rbx)
	movq	%rdi, 40(%rbx)
	movq	%r12, 48(%rbx)
	movq	%r13, 56(%rbx)
	movq	%r14, 64(%rbx)
	movq	%r15, 72(%rbx)

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
	subq	$88, %rsp

	movq	%rdx, %rcx
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
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rax, 64(%rsp)
	movq	%rbx, 72(%rsp)
	movq	%rdi, 80(%rsp)

	MULM	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP_MUL_LOW	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 0, 80(%rsp)

	addq	$88, %rsp
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
	subq	$88, %rsp

	movq	%rdx, %rcx
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
	movq	%r8, 0(%rsp)
	movq	%r9, 8(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 24(%rsp)
	movq	%r12, 32(%rsp)
	movq	%r13, 40(%rsp)
	movq	%r14, 48(%rsp)
	movq	%r15, 56(%rsp)
	movq	%rax, 64(%rsp)
	movq	%rbx, 72(%rsp)
	movq	%rdi, 80(%rsp)

	MULM	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi
	FP_MUL_LOW	0(%rsp), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rsi, %rdi, p0(%rip), 1, 80(%rsp)

	addq	$88, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
