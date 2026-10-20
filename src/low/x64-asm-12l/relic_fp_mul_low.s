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
	subq	$24, %rsp

	movq	%rdi, 0(%rsp)
	mulxq	0(%rsi), %rbx, %rax
	movq	%rbx, 8(%rsp)
	mulxq	8(%rsi), %rbx, %rbp
	addq	%rax, %rbx
	movq	%rbx, 16(%rsp)
	mulxq	16(%rsi), %r8, %rax
	adcq	%rbp, %r8
	mulxq	24(%rsi), %r9, %rbp
	adcq	%rax, %r9
	mulxq	32(%rsi), %r10, %rax
	adcq	%rbp, %r10
	mulxq	40(%rsi), %r11, %rbp
	adcq	%rax, %r11
	mulxq	48(%rsi), %rcx, %rax
	adcq	%rbp, %rcx
	mulxq	56(%rsi), %rdi, %rbp
	adcq	%rax, %rdi
	mulxq	64(%rsi), %r12, %rax
	adcq	%rbp, %r12
	mulxq	72(%rsi), %r13, %rbp
	adcq	%rax, %r13
	mulxq	80(%rsi), %r14, %rax
	adcq	%rbp, %r14
	mulxq	88(%rsi), %r15, %rbx
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
	adcx	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	mulxq	p1(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	mulxq	p2(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r8
	mulxq	p3(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r9
	mulxq	p4(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r10
	mulxq	p5(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r11
	mulxq	p6(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %rcx
	mulxq	p7(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %rdi
	mulxq	p8(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r12
	mulxq	p9(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r13
	mulxq	p10(%rip), %rax, %rbp
	adox	%rsi, %rax
	notq	%rax
	adcx	%rax, %r14
	mulxq	p11(%rip), %rax, %rsi
	adox	%rbp, %rax
	notq	%rax
	adcx	%rax, %r15
	movq	$0, %rax
	adox	%rax, %rsi
	notq	%rsi
	adcx	%rsi, %rbx
	movq	0(%rsp), %rbp

	.rept 2
	movq	8(%rsp), %rax
	subq	p0(%rip), %rax
	movq	16(%rsp), %rdx
	sbbq	p1(%rip), %rdx
	movq	%r8, 16(%rbp)
	sbbq	p2(%rip), %r8
	movq	%r9, 24(%rbp)
	sbbq	p3(%rip), %r9
	movq	%r10, 32(%rbp)
	sbbq	p4(%rip), %r10
	movq	%r11, 40(%rbp)
	sbbq	p5(%rip), %r11
	movq	%rcx, 48(%rbp)
	sbbq	p6(%rip), %rcx
	movq	%rdi, 56(%rbp)
	sbbq	p7(%rip), %rdi
	movq	%r12, 64(%rbp)
	sbbq	p8(%rip), %r12
	movq	%r13, 72(%rbp)
	sbbq	p9(%rip), %r13
	movq	%r14, 80(%rbp)
	sbbq	p10(%rip), %r14
	movq	%r15, 88(%rbp)
	sbbq	p11(%rip), %r15
	movq	%rbx, %rsi
	sbbq	$0, %rsi
	cmovc	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	cmovc	16(%rsp), %rdx
	movq	%rdx, 16(%rsp)
	cmovc	16(%rbp), %r8
	cmovc	24(%rbp), %r9
	cmovc	32(%rbp), %r10
	cmovc	40(%rbp), %r11
	cmovc	48(%rbp), %rcx
	cmovc	56(%rbp), %rdi
	cmovc	64(%rbp), %r12
	cmovc	72(%rbp), %r13
	cmovc	80(%rbp), %r14
	cmovc	88(%rbp), %r15
	cmovnc	%rsi, %rbx
	.endr

	movq	8(%rsp), %rax
	movq	%rax, 0(%rbp)
	movq	16(%rsp), %rax
	movq	%rax, 8(%rbp)
	movq	%r8, 16(%rbp)
	movq	%r9, 24(%rbp)
	movq	%r10, 32(%rbp)
	movq	%r11, 40(%rbp)
	movq	%rcx, 48(%rbp)
	movq	%rdi, 56(%rbp)
	movq	%r12, 64(%rbp)
	movq	%r13, 72(%rbp)
	movq	%r14, 80(%rbp)
	movq	%r15, 88(%rbp)

	addq	$24, %rsp
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
	subq	$208, %rsp

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
	movq	88(%rdx), %rcx
	movq	%r8, 96(%rsp)
	movq	%r9, 104(%rsp)
	movq	%r10, 112(%rsp)
	movq	%r11, 120(%rsp)
	movq	%r12, 128(%rsp)
	movq	%r13, 136(%rsp)
	movq	%r14, 144(%rsp)
	movq	%r15, 152(%rsp)
	movq	%rax, 160(%rsp)
	movq	%rbx, 168(%rsp)
	movq	%rbp, 176(%rsp)
	movq	%rcx, 184(%rsp)
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
	movq	88(%rsi), %rcx
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
	movq	%rcx, 88(%rsp)
	movq	%rdi, 192(%rsp)

	MULM	0(%rsp), 96(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rdi, %rsi
	FP_MUL_LOW	0(%rsp), 96(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rdi, %rsi, p0(%rip), 0, 192(%rsp), 200(%rsp)

	addq	$208, %rsp
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
	subq	$208, %rsp

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
	movq	88(%rdx), %rcx
	movq	%r8, 96(%rsp)
	movq	%r9, 104(%rsp)
	movq	%r10, 112(%rsp)
	movq	%r11, 120(%rsp)
	movq	%r12, 128(%rsp)
	movq	%r13, 136(%rsp)
	movq	%r14, 144(%rsp)
	movq	%r15, 152(%rsp)
	movq	%rax, 160(%rsp)
	movq	%rbx, 168(%rsp)
	movq	%rbp, 176(%rsp)
	movq	%rcx, 184(%rsp)
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
	movq	88(%rsi), %rcx
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
	movq	%rcx, 88(%rsp)
	movq	%rdi, 192(%rsp)

	MULM	0(%rsp), 96(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rdi, %rsi
	FP_MUL_LOW	0(%rsp), 96(%rsp), %r8, %r9, %r10, %r11, %r12, %r13, %r14, %r15, %rax, %rbx, %rbp, %rcx, %rdi, %rsi, p0(%rip), 1, 192(%rsp), 200(%rsp)

	addq	$208, %rsp
	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
