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

.global p0
.global p1
.global p2
.global p3
.global p4

#if RLC_OPSYS != RLC_WINDOWS

.hidden p0
.hidden p1
.hidden p2
.hidden p3
.hidden p4

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

	movq	%r8, %rdx
	movq	%r9, %rsi
	movq	%r10, %rcx
	movq	%r11, %r12
	movq	%rax, %r13
	subq	p0(%rip), %rdx
	sbbq	p1(%rip), %rsi
	sbbq	p2(%rip), %rcx
	sbbq	p3(%rip), %r12
	sbbq	p4(%rip), %r13
	cmovnc	%rdx, %r8
	cmovnc	%rsi, %r9
	cmovnc	%rcx, %r10
	cmovnc	%r12, %r11
	cmovnc	%r13, %rax
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)

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

	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11, 0(%rdi)

	ADDN	1 (RLC_FP_DIGS - 1)

	movq	40(%rdx), %r8
	adcq	40(%rsi), %r8
	movq	48(%rdx), %r9
	adcq	48(%rsi), %r9
	movq	56(%rdx), %r10
	adcq	56(%rsi), %r10
	movq	64(%rdx), %r11
	adcq	64(%rsi), %r11
	movq	72(%rdx), %rax
	adcq	72(%rsi), %rax

	movq	%r8, %rdx
	movq	%r9, %rsi
	movq	%r10, %rcx
	movq	%r11, %r12
	movq	%rax, %r13
	subq	p0(%rip), %rdx
	sbbq	p1(%rip), %rsi
	sbbq	p2(%rip), %rcx
	sbbq	p3(%rip), %r12
	sbbq	p4(%rip), %r13
	cmovnc	%rdx, %r8
	cmovnc	%rsi, %r9
	cmovnc	%rcx, %r10
	cmovnc	%r12, %r11
	cmovnc	%r13, %rax
	movq	%r8, 40(%rdi)
	movq	%r9, 48(%rdi)
	movq	%r10, 56(%rdi)
	movq	%r11, 64(%rdi)
	movq	%rax, 72(%rdi)

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

	sbbq	%rdx, %rdx
	movq	p1(%rip), %rsi
	andq	%rdx, %rsi
	movq	p2(%rip), %rcx
	andq	%rdx, %rcx
	movq	p3(%rip), %r12
	andq	%rdx, %r12
	movq	p4(%rip), %r13
	andq	%rdx, %r13
	andq	p0(%rip), %rdx
	addq	%rdx, %r8
	adcq	%rsi, %r9
	adcq	%rcx, %r10
	adcq	%r12, %r11
	adcq	%r13, %rax
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)

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

	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	%r8, 0(%rdi)

	SUBN	1 (RLC_FP_DIGS - 1)

	movq	40(%rsi), %r8
	sbbq	40(%rdx), %r8
	movq	48(%rsi), %r9
	sbbq	48(%rdx), %r9
	movq	56(%rsi), %r10
	sbbq	56(%rdx), %r10
	movq	64(%rsi), %r11
	sbbq	64(%rdx), %r11
	movq	72(%rsi), %rax
	sbbq	72(%rdx), %rax

	sbbq	%rdx, %rdx
	movq	p1(%rip), %rsi
	andq	%rdx, %rsi
	movq	p2(%rip), %rcx
	andq	%rdx, %rcx
	movq	p3(%rip), %r12
	andq	%rdx, %r12
	movq	p4(%rip), %r13
	andq	%rdx, %r13
	andq	p0(%rip), %rdx
	addq	%rdx, %r8
	adcq	%rsi, %r9
	adcq	%rcx, %r10
	adcq	%r12, %r11
	adcq	%r13, %rax
	movq	%r8, 40(%rdi)
	movq	%r9, 48(%rdi)
	movq	%r10, 56(%rdi)
	movq	%r11, 64(%rdi)
	movq	%rax, 72(%rdi)

	pop		%r13
	pop		%r12
	ret

cdecl(fp_negm_low):
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%rax, %rax
	movq	0(%rsi), %r8
	orq	8(%rsi), %r8
	orq	16(%rsi), %r8
	orq	24(%rsi), %r8
	orq	32(%rsi), %r8
	testq	%r8, %r8
	cmovnz	p0(%rip), %r8
	cmovnz	p1(%rip), %r9
	cmovnz	p2(%rip), %r10
	cmovnz	p3(%rip), %r11
	cmovnz	p4(%rip), %rax
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

	movq	%r8, %rdx
	movq	%r9, %rsi
	movq	%r10, %rcx
	movq	%r11, %r12
	movq	%rax, %r13
	subq	p0(%rip), %rdx
	sbbq	p1(%rip), %rsi
	sbbq	p2(%rip), %rcx
	sbbq	p3(%rip), %r12
	sbbq	p4(%rip), %r13
	cmovnc	%rdx, %r8
	cmovnc	%rsi, %r9
	cmovnc	%rcx, %r10
	cmovnc	%r12, %r11
	cmovnc	%r13, %rax
	movq	%r8, 0(%rdi)
	movq	%r9, 8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	movq	%rax, 32(%rdi)

	pop		%r13
	pop		%r12
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
	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11
	cmovz	%rdx, %rax

	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	32(%rsi), %rax

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
	xorq	%rax, %rax

	ret

cdecl(fp_hlvd_low):
	push	%r12
	push	%r13
	push	%r14

	movq	$1, %rdx
	andq	0(%rsi), %rdx
	movq	$0, %rdx
	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11
	movq	$P4, %rax
	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11
	cmovz	%rdx, %rax

	addq	0(%rsi), %r8
	adcq	8(%rsi), %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11
	adcq	32(%rsi), %rax
	movq	40(%rsi), %rdx
	adcq	$0, %rdx
	movq	48(%rsi), %rcx
	adcq	$0, %rcx
	movq	56(%rsi), %r12
	adcq	$0, %r12
	movq	64(%rsi), %r13
	adcq	$0, %r13
	movq	72(%rsi), %r14
	adcq	$0, %r14

	rcrq	$1, %r14
	rcrq	$1, %r13
	rcrq	$1, %r12
	rcrq	$1, %rcx
	rcrq	$1, %rdx
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
	movq	%rdx, 40(%rdi)
	movq	%rcx, 48(%rdi)
	movq	%r12, 56(%rdi)
	movq	%r13, 64(%rdi)
	movq	%r14, 72(%rdi)

	pop		%r14
	pop		%r13
	pop		%r12
	ret
