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
 * Implementation of the low-level prime field addition and subtraction
 * functions.
 *
 * @ingroup fp
 */

#include "relic_fp_low.h"
#include "macro.s"

#if defined(__APPLE__)
.section __TEXT,__const
#else
.section .rodata
#endif

.p2align 3
p0: .quad P0
p1: .quad P1
p2: .quad P2
p3: .quad P3
p4: .quad P4
p5: .quad P5
p6: .quad P6
p7: .quad P7
p8: .quad P8
p9: .quad P9
p10: .quad P10

.global p0
.global p1
.global p2
.global p3
.global p4
.global p5
.global p6
.global p7
.global p8
.global p9
.global p10

#if RLC_OPSYS != RLC_WINDOWS

.hidden p0
.hidden p1
.hidden p2
.hidden p3
.hidden p4
.hidden p5
.hidden p6
.hidden p7
.hidden p8
.hidden p9
.hidden p10

#endif

.text

.global cdecl(fp_add1_low)
.global cdecl(fp_addn_low)
.global cdecl(fp_addm_low)
.global cdecl(fp_addd_low)
.global cdecl(fp_addc_low)
.global cdecl(fp_sub1_low)
.global cdecl(fp_subn_low)
.global cdecl(fp_subm_low)
.global cdecl(fp_subd_low)
.global cdecl(fp_subc_low)
.global cdecl(fp_negm_low)
.global cdecl(fp_dbln_low)
.global cdecl(fp_dblm_low)
.global cdecl(fp_hlvm_low)
.global cdecl(fp_hlvd_low)

cdecl(fp_add1_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r10
	addq	%rdx, %r10
	movq	%r10, 0(%rdi)

	ADD1 1 (RLC_FP_DIGS - 1)
	adcq	$0, %rax

	ret

cdecl(fp_addn_low):
	xorq	%rax, %rax
	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11, 0(%rdi)

	ADDN	1 (RLC_FP_DIGS - 1)

	adcq	$0, %rax

	ret

cdecl(fp_addm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	movq	0(%rdx), %r8
	addq	0(%rsi), %r8
	movq	8(%rdx), %r9
	adcq	8(%rsi), %r9
	movq	16(%rdx), %r10
	adcq	16(%rsi), %r10
	movq	24(%rdx), %r11
	adcq	24(%rsi), %r11
	movq	32(%rdx), %r12
	adcq	32(%rsi), %r12
	movq	40(%rdx), %r13
	adcq	40(%rsi), %r13
	movq	48(%rdx), %r14
	adcq	48(%rsi), %r14
	movq	56(%rdx), %r15
	adcq	56(%rsi), %r15
	movq	64(%rdx), %rax
	adcq	64(%rsi), %rax
	movq	72(%rdx), %rbx
	adcq	72(%rsi), %rbx
	movq	80(%rdx), %rbp
	adcq	80(%rsi), %rbp

	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)
	movq	%rax, 64(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%rbp, 80(%rdi)
	subq	p0(%rip), %r8
	sbbq	p1(%rip), %r9
	sbbq	p2(%rip), %r10
	sbbq	p3(%rip), %r11
	sbbq	p4(%rip), %r12
	sbbq	p5(%rip), %r13
	sbbq	p6(%rip), %r14
	sbbq	p7(%rip), %r15
	sbbq	p8(%rip), %rax
	sbbq	p9(%rip), %rbx
	sbbq	p10(%rip), %rbp
	cmovc	0(%rdi), %r8
	cmovc	8(%rdi), %r9
	cmovc	16(%rdi), %r10
	cmovc	24(%rdi), %r11
	cmovc	32(%rdi), %r12
	cmovc	40(%rdi), %r13
	cmovc	48(%rdi), %r14
	cmovc	56(%rdi), %r15
	cmovc	64(%rdi), %rax
	cmovc	72(%rdi), %rbx
	cmovc	80(%rdi), %rbp
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)
	movq	%rax, 64(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%rbp, 80(%rdi)

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_addd_low):
	xorq	%rax, %rax
	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11, 0(%rdi)

	ADDN	1 (2 * RLC_FP_DIGS - 1)

	adcq	$0, %rax
	ret

cdecl(fp_addc_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11, 0(%rdi)

	ADDN	1 (RLC_FP_DIGS - 1)

	movq	88(%rdx), %r8
	adcq	88(%rsi), %r8
	movq	96(%rdx), %r9
	adcq	96(%rsi), %r9
	movq	104(%rdx), %r10
	adcq	104(%rsi), %r10
	movq	112(%rdx), %r11
	adcq	112(%rsi), %r11
	movq	120(%rdx), %r12
	adcq	120(%rsi), %r12
	movq	128(%rdx), %r13
	adcq	128(%rsi), %r13
	movq	136(%rdx), %r14
	adcq	136(%rsi), %r14
	movq	144(%rdx), %r15
	adcq	144(%rsi), %r15
	movq	152(%rdx), %rax
	adcq	152(%rsi), %rax
	movq	160(%rdx), %rbx
	adcq	160(%rsi), %rbx
	movq	168(%rdx), %rbp
	adcq	168(%rsi), %rbp

	movq	%r8, 88(%rdi)
	movq	%r9, 96(%rdi)
	movq	%r10, 104(%rdi)
	movq	%r11, 112(%rdi)
	movq	%r12, 120(%rdi)
	movq	%r13, 128(%rdi)
	movq	%r14, 136(%rdi)
	movq	%r15, 144(%rdi)
	movq	%rax, 152(%rdi)
	movq	%rbx, 160(%rdi)
	movq	%rbp, 168(%rdi)
	subq	p0(%rip), %r8
	sbbq	p1(%rip), %r9
	sbbq	p2(%rip), %r10
	sbbq	p3(%rip), %r11
	sbbq	p4(%rip), %r12
	sbbq	p5(%rip), %r13
	sbbq	p6(%rip), %r14
	sbbq	p7(%rip), %r15
	sbbq	p8(%rip), %rax
	sbbq	p9(%rip), %rbx
	sbbq	p10(%rip), %rbp
	cmovc	88(%rdi), %r8
	cmovc	96(%rdi), %r9
	cmovc	104(%rdi), %r10
	cmovc	112(%rdi), %r11
	cmovc	120(%rdi), %r12
	cmovc	128(%rdi), %r13
	cmovc	136(%rdi), %r14
	cmovc	144(%rdi), %r15
	cmovc	152(%rdi), %rax
	cmovc	160(%rdi), %rbx
	cmovc	168(%rdi), %rbp
	movq	%r8, 88(%rdi)
	movq	%r9, 96(%rdi)
	movq	%r10, 104(%rdi)
	movq	%r11, 112(%rdi)
	movq	%r12, 120(%rdi)
	movq	%r13, 128(%rdi)
	movq	%r14, 136(%rdi)
	movq	%r15, 144(%rdi)
	movq	%rax, 152(%rdi)
	movq	%rbx, 160(%rdi)
	movq	%rbp, 168(%rdi)

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_sub1_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r10
	subq	%rdx, %r10
	movq	%r10, 0(%rdi)

	SUB1	1 (RLC_FP_DIGS - 1)
	adcq	$0, %rax

	ret

cdecl(fp_subn_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r11
	subq	0(%rdx), %r11
	movq	%r11, 0(%rdi)

	SUBN	1 (RLC_FP_DIGS - 1)

	adcq	$0, %rax

	ret

cdecl(fp_subm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	8(%rsi), %r9
	sbbq	8(%rdx), %r9
	movq	16(%rsi), %r10
	sbbq	16(%rdx), %r10
	movq	24(%rsi), %r11
	sbbq	24(%rdx), %r11
	movq	32(%rsi), %r12
	sbbq	32(%rdx), %r12
	movq	40(%rsi), %r13
	sbbq	40(%rdx), %r13
	movq	48(%rsi), %r14
	sbbq	48(%rdx), %r14
	movq	56(%rsi), %r15
	sbbq	56(%rdx), %r15
	movq	64(%rsi), %rax
	sbbq	64(%rdx), %rax
	movq	72(%rsi), %rbx
	sbbq	72(%rdx), %rbx
	movq	80(%rsi), %rbp
	sbbq	80(%rdx), %rbp

	sbbq	%rsi, %rsi
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)
	movq	%rax, 64(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%rbp, 80(%rdi)
	movq	p0(%rip), %r8
	andq	%rsi, %r8
	movq	p1(%rip), %r9
	andq	%rsi, %r9
	movq	p2(%rip), %r10
	andq	%rsi, %r10
	movq	p3(%rip), %r11
	andq	%rsi, %r11
	movq	p4(%rip), %r12
	andq	%rsi, %r12
	movq	p5(%rip), %r13
	andq	%rsi, %r13
	movq	p6(%rip), %r14
	andq	%rsi, %r14
	movq	p7(%rip), %r15
	andq	%rsi, %r15
	movq	p8(%rip), %rax
	andq	%rsi, %rax
	movq	p9(%rip), %rbx
	andq	%rsi, %rbx
	movq	p10(%rip), %rbp
	andq	%rsi, %rbp
	addq	0(%rdi), %r8
	adcq	8(%rdi), %r9
	adcq	16(%rdi), %r10
	adcq	24(%rdi), %r11
	adcq	32(%rdi), %r12
	adcq	40(%rdi), %r13
	adcq	48(%rdi), %r14
	adcq	56(%rdi), %r15
	adcq	64(%rdi), %rax
	adcq	72(%rdi), %rbx
	adcq	80(%rdi), %rbp
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)
	movq	%rax, 64(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%rbp, 80(%rdi)

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_subd_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	%r8, 0(%rdi)

	SUBN	1 (2 * RLC_FP_DIGS - 1)

	adcq	$0, %rax
	ret

cdecl(fp_subc_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	%r8, 0(%rdi)

	SUBN	1 (RLC_FP_DIGS - 1)

	movq	88(%rsi), %r8
	sbbq	88(%rdx), %r8
	movq	96(%rsi), %r9
	sbbq	96(%rdx), %r9
	movq	104(%rsi), %r10
	sbbq	104(%rdx), %r10
	movq	112(%rsi), %r11
	sbbq	112(%rdx), %r11
	movq	120(%rsi), %r12
	sbbq	120(%rdx), %r12
	movq	128(%rsi), %r13
	sbbq	128(%rdx), %r13
	movq	136(%rsi), %r14
	sbbq	136(%rdx), %r14
	movq	144(%rsi), %r15
	sbbq	144(%rdx), %r15
	movq	152(%rsi), %rax
	sbbq	152(%rdx), %rax
	movq	160(%rsi), %rbx
	sbbq	160(%rdx), %rbx
	movq	168(%rsi), %rbp
	sbbq	168(%rdx), %rbp

	sbbq	%rsi, %rsi
	movq	%r8, 88(%rdi)
	movq	%r9, 96(%rdi)
	movq	%r10, 104(%rdi)
	movq	%r11, 112(%rdi)
	movq	%r12, 120(%rdi)
	movq	%r13, 128(%rdi)
	movq	%r14, 136(%rdi)
	movq	%r15, 144(%rdi)
	movq	%rax, 152(%rdi)
	movq	%rbx, 160(%rdi)
	movq	%rbp, 168(%rdi)
	movq	p0(%rip), %r8
	andq	%rsi, %r8
	movq	p1(%rip), %r9
	andq	%rsi, %r9
	movq	p2(%rip), %r10
	andq	%rsi, %r10
	movq	p3(%rip), %r11
	andq	%rsi, %r11
	movq	p4(%rip), %r12
	andq	%rsi, %r12
	movq	p5(%rip), %r13
	andq	%rsi, %r13
	movq	p6(%rip), %r14
	andq	%rsi, %r14
	movq	p7(%rip), %r15
	andq	%rsi, %r15
	movq	p8(%rip), %rax
	andq	%rsi, %rax
	movq	p9(%rip), %rbx
	andq	%rsi, %rbx
	movq	p10(%rip), %rbp
	andq	%rsi, %rbp
	addq	88(%rdi), %r8
	adcq	96(%rdi), %r9
	adcq	104(%rdi), %r10
	adcq	112(%rdi), %r11
	adcq	120(%rdi), %r12
	adcq	128(%rdi), %r13
	adcq	136(%rdi), %r14
	adcq	144(%rdi), %r15
	adcq	152(%rdi), %rax
	adcq	160(%rdi), %rbx
	adcq	168(%rdi), %rbp
	movq	%r8, 88(%rdi)
	movq	%r9, 96(%rdi)
	movq	%r10, 104(%rdi)
	movq	%r11, 112(%rdi)
	movq	%r12, 120(%rdi)
	movq	%r13, 128(%rdi)
	movq	%r14, 136(%rdi)
	movq	%r15, 144(%rdi)
	movq	%rax, 152(%rdi)
	movq	%rbx, 160(%rdi)
	movq	%rbp, 168(%rdi)

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_negm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%r12, %r12
	xorq	%r13, %r13
	xorq	%r14, %r14
	xorq	%r15, %r15
	xorq	%rax, %rax
	xorq	%rbx, %rbx
	xorq	%rbp, %rbp
	movq	0(%rsi), %r8
	orq	8(%rsi), %r8
	orq	16(%rsi), %r8
	orq	24(%rsi), %r8
	orq	32(%rsi), %r8
	orq	40(%rsi), %r8
	orq	48(%rsi), %r8
	orq	56(%rsi), %r8
	orq	64(%rsi), %r8
	orq	72(%rsi), %r8
	orq	80(%rsi), %r8
	testq	%r8, %r8
	cmovnz	p0(%rip), %r8
	cmovnz	p1(%rip), %r9
	cmovnz	p2(%rip), %r10
	cmovnz	p3(%rip), %r11
	cmovnz	p4(%rip), %r12
	cmovnz	p5(%rip), %r13
	cmovnz	p6(%rip), %r14
	cmovnz	p7(%rip), %r15
	cmovnz	p8(%rip), %rax
	cmovnz	p9(%rip), %rbx
	cmovnz	p10(%rip), %rbp
	subq	0(%rsi), %r8
	movq	%r8, 0(%rdi)
	sbbq	8(%rsi), %r9
	movq	%r9, 8(%rdi)
	sbbq	16(%rsi), %r10
	movq	%r10, 16(%rdi)
	sbbq	24(%rsi), %r11
	movq	%r11, 24(%rdi)
	sbbq	32(%rsi), %r12
	movq	%r12, 32(%rdi)
	sbbq	40(%rsi), %r13
	movq	%r13, 40(%rdi)
	sbbq	48(%rsi), %r14
	movq	%r14, 48(%rdi)
	sbbq	56(%rsi), %r15
	movq	%r15, 56(%rdi)
	sbbq	64(%rsi), %rax
	movq	%rax, 64(%rdi)
	sbbq	72(%rsi), %rbx
	movq	%rbx, 72(%rdi)
	sbbq	80(%rsi), %rbp
	movq	%rbp, 80(%rdi)

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_dbln_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r8
	addq	%r8, %r8
	movq	%r8, 0(%rdi)

	DBLN 1 (RLC_FP_DIGS - 1)

	adcq	$0, %rax
	ret

cdecl(fp_dblm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	movq	0(%rsi), %r8
	addq	%r8, %r8
	movq	8(%rsi), %r9
	adcq	%r9, %r9
	movq	16(%rsi), %r10
	adcq	%r10, %r10
	movq	24(%rsi), %r11
	adcq	%r11, %r11
	movq	32(%rsi), %r12
	adcq	%r12, %r12
	movq	40(%rsi), %r13
	adcq	%r13, %r13
	movq	48(%rsi), %r14
	adcq	%r14, %r14
	movq	56(%rsi), %r15
	adcq	%r15, %r15
	movq	64(%rsi), %rax
	adcq	%rax, %rax
	movq	72(%rsi), %rbx
	adcq	%rbx, %rbx
	movq	80(%rsi), %rbp
	adcq	%rbp, %rbp

	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)
	movq	%rax, 64(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%rbp, 80(%rdi)
	subq	p0(%rip), %r8
	sbbq	p1(%rip), %r9
	sbbq	p2(%rip), %r10
	sbbq	p3(%rip), %r11
	sbbq	p4(%rip), %r12
	sbbq	p5(%rip), %r13
	sbbq	p6(%rip), %r14
	sbbq	p7(%rip), %r15
	sbbq	p8(%rip), %rax
	sbbq	p9(%rip), %rbx
	sbbq	p10(%rip), %rbp
	cmovc	0(%rdi), %r8
	cmovc	8(%rdi), %r9
	cmovc	16(%rdi), %r10
	cmovc	24(%rdi), %r11
	cmovc	32(%rdi), %r12
	cmovc	40(%rdi), %r13
	cmovc	48(%rdi), %r14
	cmovc	56(%rdi), %r15
	cmovc	64(%rdi), %rax
	cmovc	72(%rdi), %rbx
	cmovc	80(%rdi), %rbp
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)
	movq	%rax, 64(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%rbp, 80(%rdi)

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_hlvm_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	movq	$1, %rdx
	andq	0(%rsi), %rdx
	movq	$0, %rdx
	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11
	movq	$P4, %r12
	movq	$P5, %r13
	movq	$P6, %r14
	movq	$P7, %r15
	movq	$P8, %rbp
	movq	$P9, %rbx
	movq	$P10, %rcx
	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11
	cmovz	%rdx, %r12
	cmovz	%rdx, %r13
	cmovz	%rdx, %r14
	cmovz	%rdx, %r15
	cmovz	%rdx, %rbp
	cmovz	%rdx, %rbx
	cmovz	%rdx, %rcx

	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	32(%rsi), %r12
	adcq	40(%rsi), %r13
	adcq	48(%rsi), %r14
	adcq	56(%rsi), %r15
	adcq	64(%rsi), %rbp
	adcq	72(%rsi), %rbx
	adcq	80(%rsi), %rcx

	rcrq	$1, %rcx
	rcrq	$1, %rbx
	rcrq	$1, %rbp
	rcrq	$1, %r15
	rcrq	$1, %r14
	rcrq	$1, %r13
	rcrq	$1, %r12
	rcrq	$1, %r11
	rcrq	$1, %r10
	rcrq	$1, %r9
	rcrq	$1, %r8

	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%r12, 32(%rdi)
	movq	%r13, 40(%rdi)
	movq	%r14, 48(%rdi)
	movq	%r15, 56(%rdi)
	movq	%rbp, 64(%rdi)
	movq	%rbx, 72(%rdi)
	movq	%rcx, 80(%rdi)
	xorq	%rax, %rax

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret

cdecl(fp_hlvd_low):
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	push	%rbx
	push	%rbp

	movq	$1, %rdx
	andq	0(%rsi), %rdx
	movq	$0, %rdx
	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11
	movq	$P4, %rax
	movq	$P5, %rcx
	movq	$P6, %rbx
	movq	$P7, %rbp
	movq	$P8, %r12
	movq	$P9, %r13
	movq	$P10, %r14
	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11
	cmovz	%rdx, %rax
	cmovz	%rdx, %rcx
	cmovz	%rdx, %rbx
	cmovz	%rdx, %rbp
	cmovz	%rdx, %r12
	cmovz	%rdx, %r13
	cmovz	%rdx, %r14

	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	32(%rsi), %rax
	adcq	40(%rsi), %rcx
	adcq	48(%rsi), %rbx
	adcq	56(%rsi), %rbp
	adcq	64(%rsi), %r12
	adcq	72(%rsi), %r13
	adcq	80(%rsi), %r14
	movq	88(%rsi), %rdx
	adcq	$0, %rdx
	movq	%rdx, 88(%rdi)
	movq	96(%rsi), %rdx
	adcq	$0, %rdx
	movq	%rdx, 96(%rdi)
	movq	104(%rsi), %rdx
	adcq	$0, %rdx
	movq	%rdx, 104(%rdi)
	movq	112(%rsi), %rdx
	adcq	$0, %rdx
	movq	%rdx, 112(%rdi)
	movq	120(%rsi), %rdx
	adcq	$0, %rdx
	movq	%rdx, 120(%rdi)
	movq	128(%rsi), %rdx
	adcq	$0, %rdx
	movq	%rdx, 128(%rdi)
	movq	136(%rsi), %rdx
	adcq	$0, %rdx
	movq	%rdx, 136(%rdi)
	movq	144(%rsi), %rdx
	adcq	$0, %rdx
	movq	%rdx, 144(%rdi)
	movq	152(%rsi), %rdx
	adcq	$0, %rdx
	movq	160(%rsi), %r15
	adcq	$0, %r15
	movq	168(%rsi), %rsi
	adcq	$0, %rsi

	rcrq	$1, %rsi
	rcrq	$1, %r15
	rcrq	$1, %rdx
	rcrq	$1, 144(%rdi)
	rcrq	$1, 136(%rdi)
	rcrq	$1, 128(%rdi)
	rcrq	$1, 120(%rdi)
	rcrq	$1, 112(%rdi)
	rcrq	$1, 104(%rdi)
	rcrq	$1, 96(%rdi)
	rcrq	$1, 88(%rdi)
	rcrq	$1, %r14
	rcrq	$1, %r13
	rcrq	$1, %r12
	rcrq	$1, %rbp
	rcrq	$1, %rbx
	rcrq	$1, %rcx
	rcrq	$1, %rax
	rcrq	$1, %r11
	rcrq	$1, %r10
	rcrq	$1, %r9
	rcrq	$1, %r8

	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)
	movq	%rcx, 40(%rdi)
	movq	%rbx, 48(%rdi)
	movq	%rbp, 56(%rdi)
	movq	%r12, 64(%rdi)
	movq	%r13, 72(%rdi)
	movq	%r14, 80(%rdi)
	movq	%rdx, 152(%rdi)
	movq	%r15, 160(%rdi)
	movq	%rsi, 168(%rdi)

	pop		%rbp
	pop		%rbx
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	ret
