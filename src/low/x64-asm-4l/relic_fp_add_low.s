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

.global p0
.global p1
.global p2
.global p3

#if RLC_OPSYS != RLC_WINDOWS

.hidden p0
.hidden p1
.hidden p2
.hidden p3

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
	addq	%rdx   , %r10
	movq	%r10   , 0(%rdi)

	ADD1 1 (RLC_FP_DIGS - 1)
	adcq	$0, %rax

	ret

cdecl(fp_addn_low):
	xorq	%rax, %rax
	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11   , 0(%rdi)

	ADDN 	1 (RLC_FP_DIGS - 1)

	adcq    $0, %rax

	ret

cdecl(fp_addm_low):
	movq	 0(%rdx), %r8
	addq	 0(%rsi), %r8
	movq	 8(%rdx), %r9
	adcq	 8(%rsi), %r9
	movq	16(%rdx), %r10
	adcq	16(%rsi), %r10
	movq	24(%rdx), %r11
	adcq	24(%rsi), %r11

	movq 	%r8 , %rax
	movq 	%r9 , %rcx
	movq 	%r10, %rdx
	movq 	%r11, %rsi

	subq	p0(%rip), %rax
	sbbq	p1(%rip), %rcx
	sbbq	p2(%rip), %rdx
	sbbq	p3(%rip), %rsi

	cmovnc	%rax, %r8
	cmovnc	%rcx, %r9
	cmovnc	%rdx, %r10
	cmovnc	%rsi, %r11

	movq	%r8 ,  0(%rdi)
	movq	%r9 ,  8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	ret

cdecl(fp_addd_low):
	xorq	%rax, %rax
	movq	0(%rdx), %r11
	addq	0(%rsi), %r11
	movq	%r11   , 0(%rdi)

	ADDN 	1 (2 * RLC_FP_DIGS - 1)

	adcq	$0, %rax
	ret

cdecl(fp_addc_low):
	movq	0(%rsi), %r8
	addq	0(%rdx), %r8
	movq	%r8    , 0(%rdi)

	ADDN	1 (RLC_FP_DIGS - 1)

	movq     32(%rsi), %r8
	adcq     32(%rdx), %r8
	movq     40(%rsi), %r9
	adcq     40(%rdx), %r9
	movq     48(%rsi), %r10
	adcq     48(%rdx), %r10
	movq     56(%rsi), %r11
	adcq     56(%rdx), %r11

	movq 	%r8 , %rax
	movq 	%r9 , %rcx
	movq 	%r10, %rdx
	movq 	%r11, %rsi

	subq	p0(%rip), %rax
	sbbq	p1(%rip), %rcx
	sbbq	p2(%rip), %rdx
	sbbq	p3(%rip), %rsi

	cmovnc	%rax, %r8
	cmovnc	%rcx, %r9
	cmovnc	%rdx, %r10
	cmovnc	%rsi, %r11

	movq	%r8 , 32(%rdi)
	movq	%r9 , 40(%rdi)
	movq	%r10, 48(%rdi)
	movq	%r11, 56(%rdi)
	ret

cdecl(fp_sub1_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r10
	subq	%rdx   , %r10
	movq	%r10   , 0(%rdi)

	SUB1 	1 (RLC_FP_DIGS - 1)
	adcq	$0, %rax

	ret

cdecl(fp_subn_low):
	xorq	%rax   , %rax
	movq	0(%rsi), %r11
	subq	0(%rdx), %r11
	movq	%r11   , 0(%rdi)

	SUBN 1 (RLC_FP_DIGS - 1)

	adcq	$0, %rax

	ret

cdecl(fp_subm_low):
	movq	 0(%rsi), %r8
	subq	 0(%rdx), %r8
	movq	 8(%rsi), %r9
	sbbq	 8(%rdx), %r9
	movq	16(%rsi), %r10
	sbbq	16(%rdx), %r10
	movq	24(%rsi), %r11
	sbbq	24(%rdx), %r11

	movq 	$0, %rax
	movq 	$0, %rcx
	movq 	$0, %rdx
	movq 	$0, %rsi

	cmovc	p0(%rip), %rax
	cmovc	p1(%rip), %rcx
	cmovc	p2(%rip), %rdx
	cmovc	p3(%rip), %rsi

	addq	%rax, %r8
	adcq	%rcx, %r9
	adcq	%rdx, %r10
	adcq	%rsi, %r11

	movq	%r8 ,  0(%rdi)
	movq	%r9 ,  8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	ret

cdecl(fp_subd_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r8
	subq	0(%rdx), %r8
	movq	%r8, 0(%rdi)

	SUBN 	1 (2 * RLC_FP_DIGS - 1)

	adcq	$0, %rax
	ret

cdecl(fp_subc_low):
	xorq    %rax,%rax
	xorq    %rcx,%rcx

	movq    0(%rsi), %r8
	subq    0(%rdx), %r8
	movq    %r8,     0(%rdi)

	SUBN 	1 (2 * RLC_FP_DIGS - 1)

	movq	$0, %r8
	movq	$0, %r9

	cmovc	p0(%rip), %rax
	cmovc	p1(%rip), %rcx
	cmovc	p2(%rip), %r8
	cmovc	p3(%rip), %r9

	addq	%rax, 32(%rdi)
	adcq	%rcx, 40(%rdi)
	adcq	%r8,  48(%rdi)
	adcq	%r9,  56(%rdi)

	ret

cdecl(fp_negm_low):
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11

	movq    0(%rsi) , %r8
	or 	    8(%rsi) , %r8
	or 	    16(%rsi), %r8
	or 	    24(%rsi), %r8
	test    %r8, %r8
	cmovnz 	p0(%rip), %r8
	cmovnz 	p1(%rip), %r9
	cmovnz 	p2(%rip), %r10
	cmovnz 	p3(%rip), %r11
	subq 	0(%rsi) , %r8
	movq 	%r8     , 0(%rdi)
	sbbq 	8(%rsi) , %r9
	movq 	%r9     , 8(%rdi)
	sbbq 	16(%rsi), %r10
	movq 	%r10    , 16(%rdi)
	sbbq 	24(%rsi), %r11
	movq 	%r11    , 24(%rdi)
	ret

cdecl(fp_dbln_low):
	xorq	%rax, %rax
	movq	0(%rsi), %r8
	addq	%r8    , %r8
	movq	%r8    , 0(%rdi)

	DBLN 1 (RLC_FP_DIGS - 1)

	adcq	$0, %rax
	ret

cdecl(fp_dblm_low):
	movq	0(%rsi) , %r8
	addq	%r8     , %r8
	movq	8(%rsi) , %r9
	adcq	%r9     , %r9
	movq	16(%rsi), %r10
	adcq	%r10    , %r10
	movq	24(%rsi), %r11
	adcq	%r11    , %r11

	movq 	%r8 , %rax
	movq 	%r9 , %rcx
	movq 	%r10, %rdx
	movq 	%r11, %rsi

	subq	p0(%rip), %rax
	sbbq	p1(%rip), %rcx
	sbbq	p2(%rip), %rdx
	sbbq	p3(%rip), %rsi

	cmovnc	%rax, %r8
	cmovnc	%rcx, %r9
	cmovnc	%rdx, %r10
	cmovnc	%rsi, %r11

	movq	%r8 ,  0(%rdi)
	movq	%r9 ,  8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	ret

cdecl(fp_hlvm_low):
	xorq	%rdx, %rdx

	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11

  	movq 	$1     ,%rax
  	movq 	0(%rsi),%rcx
  	andq 	%rcx   ,%rax

	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11

	addq	%rcx    , %r8
	adcq	8(%rsi) , %r9
	adcq	16(%rsi), %r10
	adcq	24(%rsi), %r11

  	rcrq 	$1, %r11
  	rcrq 	$1, %r10
  	rcrq 	$1, %r9
  	rcrq 	$1, %r8

	movq	%r8 ,  0(%rdi)
	movq	%r9 ,  8(%rdi)
	movq	%r10, 16(%rdi)
	movq	%r11, 24(%rdi)
	ret

cdecl(fp_hlvd_low):
	xorq	%rdx, %rdx

	movq	$P0, %r8
	movq	$P1, %r9
	movq	$P2, %r10
	movq	$P3, %r11

  	movq 	$1     ,%rax
  	movq 	0(%rsi),%rcx
  	andq 	%rcx   ,%rax

	cmovz	%rdx, %r8
	cmovz	%rdx, %r9
	cmovz	%rdx, %r10
	cmovz	%rdx, %r11

	addq	%rcx     , %r8
	adcq	8(%rsi)  , %r9
	adcq	16(%rsi) , %r10
	adcq	24(%rsi) , %r11
	movq	32(%rsi) , %rax
	adcq	$0       , %rax
	movq	40(%rsi) , %rcx
	adcq	$0       , %rcx
	movq	48(%rsi) , %rdx
	adcq	$0       , %rdx
	movq	56(%rsi) , %rsi
	adcq	$0       , %rsi

  	rcrq 	$1, %rsi
  	rcrq 	$1, %rdx
  	rcrq 	$1, %rcx
  	rcrq 	$1, %rax
  	rcrq 	$1, %r11
  	rcrq 	$1, %r10
  	rcrq 	$1, %r9
  	rcrq 	$1, %r8

  	movq 	%rsi, 56(%rdi)
  	movq 	%rdx, 48(%rdi)
  	movq 	%rcx, 40(%rdi)
  	movq 	%rax, 32(%rdi)
  	movq 	%r11, 24(%rdi)
  	movq 	%r10, 16(%rdi)
  	movq 	%r9 ,  8(%rdi)
  	movq 	%r8 ,  0(%rdi)
	ret
