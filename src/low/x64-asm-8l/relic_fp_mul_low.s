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
	mulxq	8(%rsi), %r9, %r15
	addq	%rax, %r9
	mulxq	16(%rsi), %r10, %rax
	adcq	%r15, %r10
	mulxq	24(%rsi), %r11, %r15
	adcq	%rax, %r11
	mulxq	32(%rsi), %rcx, %rax
	adcq	%r15, %rcx
	mulxq	40(%rsi), %rdi, %r15
	adcq	%rax, %rdi
	mulxq	48(%rsi), %r12, %rax
	adcq	%r15, %r12
	mulxq	56(%rsi), %r13, %r14
	adcq	%rax, %r13
	adcq	$0, %r14

	movq	%r13, %rax
	shrdq	$BARS, %r14, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	xorq	%rax, %rax
	stc
	mulxq	p0(%rip), %rax, %r15
	notq	%rax
	adcx	%rax, %r8
	mulxq	p1(%rip), %rax, %rsi
	adox	%r15, %rax
	notq	%rax
	adcx	%rax, %r9
	mulxq	p2(%rip), %rax, %r15
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r10
	mulxq	p3(%rip), %rax, %rsi
	adox	%r15, %rax
	notq	%rax
	adcx	%rax, %r11
	mulxq	p4(%rip), %rax, %r15
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %rcx
	mulxq	p5(%rip), %rax, %rsi
	adox	%r15, %rax
	notq	%rax
	adcx	%rax, %rdi
	mulxq	p6(%rip), %rax, %r15
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r12
	mulxq	p7(%rip), %rax, %rsi
	adox	%r15, %rax
	notq	%rax
	adcx	%rax, %r13
	movq	$0, %rax
	adox	%rax, %rsi
	notq	%rsi
	adcx	%rsi, %r14
	movq	0(%rsp), %rbp

	.rept 2
	movq	%r8, 0(%rbp)
	subq	p0(%rip), %r8
	movq	%r9, 8(%rbp)
	sbbq	p1(%rip), %r9
	movq	%r10, 16(%rbp)
	sbbq	p2(%rip), %r10
	movq	%r11, 24(%rbp)
	sbbq	p3(%rip), %r11
	movq	%rcx, %rbx
	sbbq	p4(%rip), %rbx
	movq	%rdi, %r15
	sbbq	p5(%rip), %r15
	movq	%r12, %rsi
	sbbq	p6(%rip), %rsi
	movq	%r13, %rdx
	sbbq	p7(%rip), %rdx
	movq	%r14, %rax
	sbbq	$0, %rax
	cmovc	0(%rbp), %r8
	cmovc	8(%rbp), %r9
	cmovc	16(%rbp), %r10
	cmovc	24(%rbp), %r11
	cmovnc	%rbx, %rcx
	cmovnc	%r15, %rdi
	cmovnc	%rsi, %r12
	cmovnc	%rdx, %r13
	cmovnc	%rax, %r14
	.endr

	movq	%r8, 0(%rbp)
	movq	%r9, 8(%rbp)
	movq	%r10, 16(%rbp)
	movq	%r11, 24(%rbp)
	movq	%rcx, 32(%rbp)
	movq	%rdi, 40(%rbp)
	movq	%r12, 48(%rbp)
	movq	%r13, 56(%rbp)

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

	movq	%rdx, %rcx

	MULM	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp
	FP_MUL_LOW	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 0

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

	movq	%rdx, %rcx

	MULM	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp
	FP_MUL_LOW	0(%rsi), 0(%rcx), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rbx, %rbp, %rax, p0(%rip), 1

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
