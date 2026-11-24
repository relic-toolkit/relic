/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2023 RELIC Authors
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
	subq	$16, %rsp

	movq	%rdi, 0(%rsp)
	mulxq	0(%rsi), %rbx, %rax
	movq	%rbx, 8(%rsp)
	mulxq	8(%rsi), %r8, %rbp
	addq	%rax, %r8
	mulxq	16(%rsi), %r9, %rax
	adcq	%rbp, %r9
	mulxq	24(%rsi), %r10, %rbp
	adcq	%rax, %r10
	mulxq	32(%rsi), %r11, %rax
	adcq	%rbp, %r11
	mulxq	40(%rsi), %rcx, %rbp
	adcq	%rax, %rcx
	mulxq	48(%rsi), %rdi, %rax
	adcq	%rbp, %rdi
	mulxq	56(%rsi), %r12, %rbp
	adcq	%rax, %r12
	mulxq	64(%rsi), %r13, %rax
	adcq	%rbp, %r13
	mulxq	72(%rsi), %r14, %rbp
	adcq	%rax, %r14
	mulxq	80(%rsi), %r15, %rbx
	adcq	%rbp, %r15
	adcq	$0, %rbx

	movq	%r15, %rax
	shrdq	$BARS, %rbx, %rax
	movq	$BAR, %rdx
	mulxq	%rax, %rax, %rdx

	xorq	%rax, %rax
	stc
	mulxq	p0(%rip), %rax, %rbp
	notq	%rax
	adcx	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	mulxq	p1(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r8
	mulxq	p2(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r9
	mulxq	p3(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r10
	mulxq	p4(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r11
	mulxq	p5(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %rcx
	mulxq	p6(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %rdi
	mulxq	p7(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r12
	mulxq	p8(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r13
	mulxq	p9(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r14
	mulxq	p10(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r15
	movq	0(%rsp), %rbx

	.rept 2
	movq	8(%rsp), %rax
	subq	p0(%rip), %rax
	movq	%r8, 8(%rbx)
	sbbq	p1(%rip), %r8
	movq	%r9, 16(%rbx)
	sbbq	p2(%rip), %r9
	movq	%r10, 24(%rbx)
	sbbq	p3(%rip), %r10
	movq	%r11, 32(%rbx)
	sbbq	p4(%rip), %r11
	movq	%rcx, 40(%rbx)
	sbbq	p5(%rip), %rcx
	movq	%rdi, 48(%rbx)
	sbbq	p6(%rip), %rdi
	movq	%r12, 56(%rbx)
	sbbq	p7(%rip), %r12
	movq	%r13, %rbp
	sbbq	p8(%rip), %rbp
	movq	%r14, %rsi
	sbbq	p9(%rip), %rsi
	movq	%r15, %rdx
	sbbq	p10(%rip), %rdx
	cmovc	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	cmovc	8(%rbx), %r8
	cmovc	16(%rbx), %r9
	cmovc	24(%rbx), %r10
	cmovc	32(%rbx), %r11
	cmovc	40(%rbx), %rcx
	cmovc	48(%rbx), %rdi
	cmovc	56(%rbx), %r12
	cmovnc	%rbp, %r13
	cmovnc	%rsi, %r14
	cmovnc	%rdx, %r15
	.endr

	movq	8(%rsp), %rax
	movq	%rax, 0(%rbx)
	movq	%r8, 8(%rbx)
	movq	%r9, 16(%rbx)
	movq	%r10, 24(%rbx)
	movq	%r11, 32(%rbx)
	movq	%rcx, 40(%rbx)
	movq	%rdi, 48(%rbx)
	movq	%r12, 56(%rbx)
	movq	%r13, 64(%rbx)
	movq	%r14, 72(%rbx)
	movq	%r15, 80(%rbx)

	addq	$16, %rsp
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
	subq	$184, %rsp

	movq	0(%rdx), %r8
	movq	8(%rdx), %r9
	movq	16(%rdx), %r10
	movq	24(%rdx), %r11
	movq	32(%rdx), %r12
	movq	40(%rdx), %r13
	movq	48(%rdx), %r14
	movq	56(%rdx), %r15
	movq	64(%rdx), %rax
	movq	72(%rdx), %rbx
	movq	80(%rdx), %rbp
	movq	%r8, 88(%rsp)
	movq	%r9, 96(%rsp)
	movq	%r10, 104(%rsp)
	movq	%r11, 112(%rsp)
	movq	%r12, 120(%rsp)
	movq	%r13, 128(%rsp)
	movq	%r14, 136(%rsp)
	movq	%r15, 144(%rsp)
	movq	%rax, 152(%rsp)
	movq	%rbx, 160(%rsp)
	movq	%rbp, 168(%rsp)
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
	movq	80(%rsi), %rbp
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
	movq	%rbp, 80(%rsp)
	movq	%rdi, 176(%rsp)

	MULM	0(%rsp), 88(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rsi
	FP_MUL_LOW	0(%rsp), 88(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rsi, %rdi, p0(%rip), 0, 176(%rsp)

	addq	$184, %rsp
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
	subq	$184, %rsp

	movq	0(%rdx), %r8
	movq	8(%rdx), %r9
	movq	16(%rdx), %r10
	movq	24(%rdx), %r11
	movq	32(%rdx), %r12
	movq	40(%rdx), %r13
	movq	48(%rdx), %r14
	movq	56(%rdx), %r15
	movq	64(%rdx), %rax
	movq	72(%rdx), %rbx
	movq	80(%rdx), %rbp
	movq	%r8, 88(%rsp)
	movq	%r9, 96(%rsp)
	movq	%r10, 104(%rsp)
	movq	%r11, 112(%rsp)
	movq	%r12, 120(%rsp)
	movq	%r13, 128(%rsp)
	movq	%r14, 136(%rsp)
	movq	%r15, 144(%rsp)
	movq	%rax, 152(%rsp)
	movq	%rbx, 160(%rsp)
	movq	%rbp, 168(%rsp)
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
	movq	80(%rsi), %rbp
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
	movq	%rbp, 80(%rsp)
	movq	%rdi, 176(%rsp)

	MULM	0(%rsp), 88(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rsi
	FP_MUL_LOW	0(%rsp), 88(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rsi, %rdi, p0(%rip), 1, 176(%rsp)

	addq	$184, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
