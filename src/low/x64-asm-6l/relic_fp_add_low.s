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

.global p0
.global p1
.global p2
.global p3
.global p4
.global p5

#if RLC_OPSYS != RLC_WINDOWS

.hidden p0
.hidden p1
.hidden p2
.hidden p3
.hidden p4
.hidden p5

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
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	movq	0(%rdx), %r8
	addq	0(%rsi), %r8
	movq	8(%rdx), %r9
	adcq	8(%rsi), %r9
	movq	16(%rdx), %r10
	adcq	16(%rsi), %r10
	movq	24(%rdx), %r11
	adcq	24(%rsi), %r11
	movq	32(%rdx), %rax
	adcq	32(%rsi), %rax
	movq	40(%rdx), %rcx
	adcq	40(%rsi), %rcx

	movq	%r8, %rdx
	movq	%r9, %rsi
	movq	%r10, %rbx
	movq	%r11, %rbp
	movq	%rax, %r12
	movq	%rcx, %r13
	subq	p0(%rip), %rdx
	sbbq	p1(%rip), %rsi
	sbbq	p2(%rip), %rbx
	sbbq	p3(%rip), %rbp
	sbbq	p4(%rip), %r12
	sbbq	p5(%rip), %r13
	cmovnc	%rdx, %r8
	cmovnc	%rsi, %r9
	cmovnc	%rbx, %r10
	cmovnc	%rbp, %r11
	cmovnc	%r12, %rax
	cmovnc	%r13, %rcx
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)
	movq	%rcx, 40(%rdi)

	pop		%r13
	pop		%r12
	pop		%rbp
	pop		%rbx
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
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11, 0(%rdi)

	ADDN	1 (RLC_FP_DIGS - 1)

	movq	48(%rdx), %r8
	adcq	48(%rsi), %r8
	movq	56(%rdx), %r9
	adcq	56(%rsi), %r9
	movq	64(%rdx), %r10
	adcq	64(%rsi), %r10
	movq	72(%rdx), %r11
	adcq	72(%rsi), %r11
	movq	80(%rdx), %rax
	adcq	80(%rsi), %rax
	movq	88(%rdx), %rcx
	adcq	88(%rsi), %rcx

	movq	%r8, %rdx
	movq	%r9, %rsi
	movq	%r10, %rbx
	movq	%r11, %rbp
	movq	%rax, %r12
	movq	%rcx, %r13
	subq	p0(%rip), %rdx
	sbbq	p1(%rip), %rsi
	sbbq	p2(%rip), %rbx
	sbbq	p3(%rip), %rbp
	sbbq	p4(%rip), %r12
	sbbq	p5(%rip), %r13
	cmovnc	%rdx, %r8
	cmovnc	%rsi, %r9
	cmovnc	%rbx, %r10
	cmovnc	%rbp, %r11
	cmovnc	%r12, %rax
	cmovnc	%r13, %rcx
	movq	%r8, 48(%rdi)
	movq	%r9, 56(%rdi)
	movq	%r10, 64(%rdi)
	movq	%r11, 72(%rdi)
	movq	%rax, 80(%rdi)
	movq	%rcx, 88(%rdi)

	pop		%r13
	pop		%r12
	pop		%rbp
	pop		%rbx
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
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	8(%rsi), %r9
	sbbq	8(%rdx), %r9
	movq	16(%rsi), %r10
	sbbq	16(%rdx), %r10
	movq	24(%rsi), %r11
	sbbq	24(%rdx), %r11
	movq	32(%rsi), %rax
	sbbq	32(%rdx), %rax
	movq	40(%rsi), %rcx
	sbbq	40(%rdx), %rcx

	sbbq	%rdx, %rdx
	movq	p1(%rip), %rsi
	andq	%rdx, %rsi
	movq	p2(%rip), %rbx
	andq	%rdx, %rbx
	movq	p3(%rip), %rbp
	andq	%rdx, %rbp
	movq	p4(%rip), %r12
	andq	%rdx, %r12
	movq	p5(%rip), %r13
	andq	%rdx, %r13
	andq	p0(%rip), %rdx
	addq	%rdx, %r8
	adcq	%rsi, %r9
	adcq	%rbx, %r10
	adcq	%rbp, %r11
	adcq	%r12, %rax
	adcq	%r13, %rcx
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)
	movq	%rcx, 40(%rdi)

	pop		%r13
	pop		%r12
	pop		%rbp
	pop		%rbx
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
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	%r8, 0(%rdi)

	SUBN	1 (RLC_FP_DIGS - 1)

	movq	48(%rsi), %r8
	sbbq	48(%rdx), %r8
	movq	56(%rsi), %r9
	sbbq	56(%rdx), %r9
	movq	64(%rsi), %r10
	sbbq	64(%rdx), %r10
	movq	72(%rsi), %r11
	sbbq	72(%rdx), %r11
	movq	80(%rsi), %rax
	sbbq	80(%rdx), %rax
	movq	88(%rsi), %rcx
	sbbq	88(%rdx), %rcx

	sbbq	%rdx, %rdx
	movq	p1(%rip), %rsi
	andq	%rdx, %rsi
	movq	p2(%rip), %rbx
	andq	%rdx, %rbx
	movq	p3(%rip), %rbp
	andq	%rdx, %rbp
	movq	p4(%rip), %r12
	andq	%rdx, %r12
	movq	p5(%rip), %r13
	andq	%rdx, %r13
	andq	p0(%rip), %rdx
	addq	%rdx, %r8
	adcq	%rsi, %r9
	adcq	%rbx, %r10
	adcq	%rbp, %r11
	adcq	%r12, %rax
	adcq	%r13, %rcx
	movq	%r8, 48(%rdi)
	movq	%r9, 56(%rdi)
	movq	%r10, 64(%rdi)
	movq	%r11, 72(%rdi)
	movq	%rax, 80(%rdi)
	movq	%rcx, 88(%rdi)

	pop		%r13
	pop		%r12
	pop		%rbp
	pop		%rbx
	ret

cdecl(fp_negm_low):
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%rax, %rax
	xorq	%rcx, %rcx
	movq	0(%rsi), %r8
	orq	8(%rsi), %r8
	orq	16(%rsi), %r8
	orq	24(%rsi), %r8
	orq	32(%rsi), %r8
	orq	40(%rsi), %r8
	testq	%r8, %r8
	cmovnz	p0(%rip), %r8
	cmovnz	p1(%rip), %r9
	cmovnz	p2(%rip), %r10
	cmovnz	p3(%rip), %r11
	cmovnz	p4(%rip), %rax
	cmovnz	p5(%rip), %rcx
	subq	0(%rsi), %r8
	movq	%r8, 0(%rdi)
	sbbq	8(%rsi), %r9
	movq	%r9, 8(%rdi)
	sbbq	16(%rsi), %r10
	movq	%r10, 16(%rdi)
	sbbq	24(%rsi), %r11
	movq	%r11, 24(%rdi)
	sbbq	32(%rsi), %rax
	movq	%rax, 32(%rdi)
	sbbq	40(%rsi), %rcx
	movq	%rcx, 40(%rdi)

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
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13

	movq	0(%rsi), %r8
	addq	%r8, %r8
	movq	8(%rsi), %r9
	adcq	%r9, %r9
	movq	16(%rsi), %r10
	adcq	%r10, %r10
	movq	24(%rsi), %r11
	adcq	%r11, %r11
	movq	32(%rsi), %rax
	adcq	%rax, %rax
	movq	40(%rsi), %rcx
	adcq	%rcx, %rcx

	movq	%r8, %rdx
	movq	%r9, %rsi
	movq	%r10, %rbx
	movq	%r11, %rbp
	movq	%rax, %r12
	movq	%rcx, %r13
	subq	p0(%rip), %rdx
	sbbq	p1(%rip), %rsi
	sbbq	p2(%rip), %rbx
	sbbq	p3(%rip), %rbp
	sbbq	p4(%rip), %r12
	sbbq	p5(%rip), %r13
	cmovnc	%rdx, %r8
	cmovnc	%rsi, %r9
	cmovnc	%rbx, %r10
	cmovnc	%rbp, %r11
	cmovnc	%r12, %rax
	cmovnc	%r13, %rcx
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)
	movq	%rcx, 40(%rdi)

	pop		%r13
	pop		%r12
	pop		%rbp
	pop		%rbx
	ret

cdecl(fp_hlvm_low):
	movq	$1, %rdx
	andq	0(%rsi), %rdx
	movq	$0, %rdx
	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11
	movq	$P4, %rax
	movq	$P5, %rcx
	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11
	cmovz	%rdx, %rax
	cmovz	%rdx, %rcx

	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	32(%rsi), %rax
	adcq	40(%rsi), %rcx

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
	xorq	%rax, %rax

	ret

cdecl(fp_hlvd_low):
	push	%r12
	push	%r13
	push	%r14
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
	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11
	cmovz	%rdx, %rax
	cmovz	%rdx, %rcx

	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	32(%rsi), %rax
	adcq	40(%rsi), %rcx
	movq	48(%rsi), %rdx
	adcq	$0, %rdx
	movq	56(%rsi), %rbx
	adcq	$0, %rbx
	movq	64(%rsi), %rbp
	adcq	$0, %rbp
	movq	72(%rsi), %r12
	adcq	$0, %r12
	movq	80(%rsi), %r13
	adcq	$0, %r13
	movq	88(%rsi), %r14
	adcq	$0, %r14

	rcrq	$1, %r14
	rcrq	$1, %r13
	rcrq	$1, %r12
	rcrq	$1, %rbp
	rcrq	$1, %rbx
	rcrq	$1, %rdx
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
	movq	%rdx, 48(%rdi)
	movq	%rbx, 56(%rdi)
	movq	%rbp, 64(%rdi)
	movq	%r12, 72(%rdi)
	movq	%r13, 80(%rdi)
	movq	%r14, 88(%rdi)

	pop		%rbp
	pop		%rbx
	pop		%r14
	pop		%r13
	pop		%r12
	ret
