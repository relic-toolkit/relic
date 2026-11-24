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

#include "relic_fp_low.h"

/**
 * @file
 *
 * Implementation of low-level prime field multiplication.
 *
 * @ingroup fp
 */

#if FP_PRIME == 768
#define P0	0x591ADE1200800001
#define P1	0xACE2A12843C534B1
#define P2	0x9FBEDDEE98705380
#define P3	0x1429BCDA53E20A8F
#define P4	0x31B6221831F61A72
#define P5	0x828EC90E320E3793
#define P6	0x9AD532EA851862BD
#define P7	0x6A6D9D80470079AE
#define P8	0xBA1AF14A9BC88DBA
#define P9	0x172EC88A91CFC7D2
#define P10	0x3290395E476657BA
#define P11	0xFFFFFFE4FF400142
#define U0	0x471A9E12007FFFFF
#define BAR	0x8000000D806000CB
#define BARS	63
#elif FP_PRIME == 766
#define P0	0xF45D1E791E054605
#define P1	0xFCBC4220020A6592
#define P2	0x211730168CD3106C
#define P3	0xC81A3A94170A2E5A
#define P4	0x04A837318C7897B6
#define P5	0xA2902CAC0A117EAD
#define P6	0x4C8C62B406D882C8
#define P7	0xDC0F8D8300A6748A
#define P8	0x67D35D389C7BD43C
#define P9	0x89F38FC6E7249EF1
#define P10	0xC2E122127943E41E
#define P11	0x3FFFB8002607F379
#define U0	0xF282381A203F6933
#define BAR	0x8000900055F02428
#define BARS	61
#elif FP_PRIME == 765
#define P0	0x1000EFC080000001
#define P1	0x0000000038223FF0
#define P2	0x0000000000000000
#define P3	0x0140000000000000
#define P4	0x93D3AA2586A9BB7B
#define P5	0x2C9088558A226AF0
#define P6	0x7071D6BA0697D5A1
#define P7	0xFE00400021385D1A
#define P8	0x1629227BB6527E4E
#define P9	0xD4A66E04AA631EEA
#define P10	0xBC5664C6F237BCB4
#define P11	0x166A30BEAF4CE221
#define U0	0xD000EFC07FFFFFFF
#define BAR	0xB6BC81C39E9E28BA
#define BARS	60
#else
#error "x64-asm-12l supports only FP_PRIME = 765, 766 or 768."
#endif

#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

#if defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif

#if defined(__APPLE__)
.section __TEXT,__const
#else
.section .rodata
#endif
.p2align 3
ones:	.quad	-1
zero:	.quad	0

.text

.macro ADD1 i j
	movq	8*\i(%rsi), %r10
	adcq	$0, %r10
	movq	%r10, 8*\i(%rdi)
	.if \i - \j
		ADD1 "(\i + 1)" \j
	.endif
.endm

.macro ADDN i j
	movq	8*\i(%rdx), %r11
	adcq	8*\i(%rsi), %r11
	movq	%r11, 8*\i(%rdi)
	.if \i - \j
		ADDN "(\i + 1)" \j
	.endif
.endm

.macro SUB1 i j
	movq	8*\i(%rsi),%r10
	sbbq	$0, %r10
	movq	%r10,8*\i(%rdi)
	.if \i - \j
		SUB1 "(\i + 1)" \j
	.endif
.endm

.macro SUBN i j
	movq	8*\i(%rsi), %r8
	sbbq	8*\i(%rdx), %r8
	movq	%r8, 8*\i(%rdi)
	.if \i - \j
		SUBN "(\i + 1)" \j
	.endif
.endm

.macro DBLN i j
	movq	8*\i(%rsi), %r8
	adcq	%r8, %r8
	movq	%r8, 8*\i(%rdi)
	.if \i - \j
		DBLN "(\i + 1)" \j
	.endif
.endm

.macro MULM A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12, Z13
	movq	0+\A, %rdx
	mulx	0+\B, \Z0, \Z1
	mulx	8+\B, \Z13, \Z2
	addq	\Z13, \Z1
	mulx	16+\B, \Z13, \Z3
	adcq	\Z13, \Z2
	mulx	24+\B, \Z13, \Z4
	adcq	\Z13, \Z3
	mulx	32+\B, \Z13, \Z5
	adcq	\Z13, \Z4
	mulx	40+\B, \Z13, \Z6
	adcq	\Z13, \Z5
	mulx	48+\B, \Z13, \Z7
	adcq	\Z13, \Z6
	mulx	56+\B, \Z13, \Z8
	adcq	\Z13, \Z7
	mulx	64+\B, \Z13, \Z9
	adcq	\Z13, \Z8
	mulx	72+\B, \Z13, \Z10
	adcq	\Z13, \Z9
	mulx	80+\B, \Z13, \Z11
	adcq	\Z13, \Z10
	mulx	88+\B, \Z13, \Z12
	adcq	\Z13, \Z11
	adcq	$0, \Z12
.endm

.macro MULADD1 Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, X, T, ZR, M, K
	mulx	0+\M, \T, \X
	adox	\T, \Z0
	adox	\X, \Z1
	mulx	8+\M, \T, \X
	adcx	\T, \Z1
	adox	\X, \Z2
	mulx	16+\M, \T, \X
	adcx	\T, \Z2
	adox	\X, \Z3
	mulx	24+\M, \T, \X
	adcx	\T, \Z3
	adox	\X, \Z4
	mulx	32+\M, \T, \X
	adcx	\T, \Z4
	adox	\X, \Z5
	mulx	40+\M, \T, \X
	adcx	\T, \Z5
	adox	\X, \Z6
	mulx	48+\M, \T, \X
	adcx	\T, \Z6
	adox	\X, \Z7
	mulx	56+\M, \T, \X
	adcx	\T, \Z7
	adox	\X, \Z8
	mulx	64+\M, \T, \X
	adcx	\T, \Z8
	adox	\X, \Z9
	mulx	72+\M, \T, \X
	adcx	\T, \Z9
	adox	\X, \Z10
	mulx	80+\M, \T, \X
	adcx	\T, \Z10
	adox	\X, \Z11
	mulx	88+\M, \T, \X
	adcx	\T, \Z11
	adox	\ZR, \X
#if FP_PRIME == 768
	adcx	\K, \X
#else
	adcx	\ZR, \X
#endif
.endm

.macro MULRDC1 Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12, T, ZR, P
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T
	mulx	0+\P, \T, \T
	adcx	ones(%rip), \Z0
	adox	\T, \Z1
	mulx	8+\P, \T, \Z0
	adcx	\T, \Z1
	adox	\Z0, \Z2
	mulx	16+\P, \T, \Z0
	adcx	\T, \Z2
	adox	\Z0, \Z3
	mulx	24+\P, \T, \Z0
	adcx	\T, \Z3
	adox	\Z0, \Z4
	mulx	32+\P, \T, \Z0
	adcx	\T, \Z4
	adox	\Z0, \Z5
	mulx	40+\P, \T, \Z0
	adcx	\T, \Z5
	adox	\Z0, \Z6
	mulx	48+\P, \T, \Z0
	adcx	\T, \Z6
	adox	\Z0, \Z7
	mulx	56+\P, \T, \Z0
	adcx	\T, \Z7
	adox	\Z0, \Z8
	mulx	64+\P, \T, \Z0
	adcx	\T, \Z8
	adox	\Z0, \Z9
	mulx	72+\P, \T, \Z0
	adcx	\T, \Z9
	adox	\Z0, \Z10
	mulx	80+\P, \T, \Z0
	adcx	\T, \Z10
	adox	\Z0, \Z11
	mulx	88+\P, \T, \Z0
	adcx	\T, \Z11
	adox	\Z0, \Z12
	adcx	\ZR, \Z12
#if FP_PRIME == 768
	movq	$0, \Z0
	adox	\ZR, \Z0
	adcx	\ZR, \Z0
#endif
.endm

.macro FINALC V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, C0, D, H
	movq	\V0, 0+\D
	movq	\V1, 8+\D
	movq	\V2, 16+\D
	movq	\V3, 24+\D
	movq	\V4, 32+\D
	movq	\V5, 40+\D
	movq	\V6, 48+\D
	movq	\V7, 56+\D
	movq	\V8, 64+\D
	movq	\V9, 72+\D
	movq	\V10, 80+\D
	movq	\V11, \C0
	subq	p0(%rip), \V0
	sbbq	p1(%rip), \V1
	sbbq	p2(%rip), \V2
	sbbq	p3(%rip), \V3
	sbbq	p4(%rip), \V4
	sbbq	p5(%rip), \V5
	sbbq	p6(%rip), \V6
	sbbq	p7(%rip), \V7
	sbbq	p8(%rip), \V8
	sbbq	p9(%rip), \V9
	sbbq	p10(%rip), \V10
	sbbq	p11(%rip), \C0
#if FP_PRIME == 768
	sbbq	$0, \H
#endif
	cmovc	0+\D, \V0
	cmovc	8+\D, \V1
	cmovc	16+\D, \V2
	cmovc	24+\D, \V3
	cmovc	32+\D, \V4
	cmovc	40+\D, \V5
	cmovc	48+\D, \V6
	cmovc	56+\D, \V7
	cmovc	64+\D, \V8
	cmovc	72+\D, \V9
	cmovc	80+\D, \V10
	cmovc	\V11, \C0
	movq	\V0, 0+\D
	movq	\V1, 8+\D
	movq	\V2, 16+\D
	movq	\V3, 24+\D
	movq	\V4, 32+\D
	movq	\V5, 40+\D
	movq	\V6, 48+\D
	movq	\V7, 56+\D
	movq	\V8, 64+\D
	movq	\V9, 72+\D
	movq	\V10, 80+\D
	movq	\C0, 88+\D
.endm

.macro RDCSTEP Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T, ZR, P
	movq	$U0, %rdx
	mulx	\Z0, %rdx, \T
	mulx	0+\P, \T, \T
	adcx	ones(%rip), \Z0
	adox	\T, \Z1
	mulx	8+\P, \T, \Z0
	adcx	\T, \Z1
	adox	\Z0, \Z2
	mulx	16+\P, \T, \Z0
	adcx	\T, \Z2
	adox	\Z0, \Z3
	mulx	24+\P, \T, \Z0
	adcx	\T, \Z3
	adox	\Z0, \Z4
	mulx	32+\P, \T, \Z0
	adcx	\T, \Z4
	adox	\Z0, \Z5
	mulx	40+\P, \T, \Z0
	adcx	\T, \Z5
	adox	\Z0, \Z6
	mulx	48+\P, \T, \Z0
	adcx	\T, \Z6
	adox	\Z0, \Z7
	mulx	56+\P, \T, \Z0
	adcx	\T, \Z7
	adox	\Z0, \Z8
	mulx	64+\P, \T, \Z0
	adcx	\T, \Z8
	adox	\Z0, \Z9
	mulx	72+\P, \T, \Z0
	adcx	\T, \Z9
	adox	\Z0, \Z10
	mulx	80+\P, \T, \Z0
	adcx	\T, \Z10
	adox	\Z0, \Z11
	mulx	88+\P, \T, \Z0
	adcx	\T, \Z11
	adox	\ZR, \Z0
	adcx	\ZR, \Z0
.endm

.macro RDCN Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, P
	RDCSTEP	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, zero(%rip), \P
	RDCSTEP	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \T0, zero(%rip), \P
	RDCSTEP	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \T0, zero(%rip), \P
	RDCSTEP	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \T0, zero(%rip), \P
	RDCSTEP	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \T0, zero(%rip), \P
	RDCSTEP	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, zero(%rip), \P
	RDCSTEP	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, zero(%rip), \P
	RDCSTEP	\Z7, \Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, zero(%rip), \P
	RDCSTEP	\Z8, \Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, zero(%rip), \P
	RDCSTEP	\Z9, \Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, zero(%rip), \P
	RDCSTEP	\Z10, \Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, zero(%rip), \P
	RDCSTEP	\Z11, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, zero(%rip), \P
.endm

.macro ADDH Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, H0, H1, H2, H3, H4, H5, H6, H7, H8, H9, H10, H11
	addq	\H0, \Z0
	adcq	\H1, \Z1
	adcq	\H2, \Z2
	adcq	\H3, \Z3
	adcq	\H4, \Z4
	adcq	\H5, \Z5
	adcq	\H6, \Z6
	adcq	\H7, \Z7
	adcq	\H8, \Z8
	adcq	\H9, \Z9
	adcq	\H10, \Z10
	adcq	\H11, \Z11
.endm

.macro FP_RDCN_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, T0, P, C0, CP, H
	movq	0+\A, \Z0
	movq	8+\A, \Z1
	movq	16+\A, \Z2
	movq	24+\A, \Z3
	movq	32+\A, \Z4
	movq	40+\A, \Z5
	movq	48+\A, \Z6
	movq	56+\A, \Z7
	movq	64+\A, \Z8
	movq	72+\A, \Z9
	movq	80+\A, \Z10
	movq	88+\A, \Z11
	xorq	\T0, \T0
	RDCN	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \T0, \P
	ADDH	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, 96+\A, 104+\A, 112+\A, 120+\A, 128+\A, 136+\A, 144+\A, 152+\A, 160+\A, 168+\A, 176+\A, 184+\A
#if FP_PRIME == 768
	movq	$0, \H
	adcq	$0, \H
#endif
	movq	\CP, \T0
	FINALC	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \C0, 0(\T0), \H
.endm

.macro SQRN A, O, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1
	movq	0+\A, %rdx
	mulx	8+\A, \Z0, \Z1
	movq	\Z0, 8+\O
	mulx	16+\A, \T0, \Z2
	addq	\T0, \Z1
	movq	\Z1, 16+\O
	mulx	24+\A, \T0, \Z3
	adcq	\T0, \Z2
	mulx	32+\A, \T0, \Z4
	adcq	\T0, \Z3
	mulx	40+\A, \T0, \Z5
	adcq	\T0, \Z4
	mulx	48+\A, \T0, \Z6
	adcq	\T0, \Z5
	mulx	56+\A, \T0, \Z7
	adcq	\T0, \Z6
	mulx	64+\A, \T0, \Z8
	adcq	\T0, \Z7
	mulx	72+\A, \T0, \Z9
	adcq	\T0, \Z8
	mulx	80+\A, \T0, \Z0
	adcq	\T0, \Z9
	mulx	88+\A, \T0, \Z1
	adcq	\T0, \Z0
	adcq	$0, \Z1

	movq	8+\A, %rdx
	xorq	\T0, \T0
	mulx	16+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	movq	\Z2, 24+\O
	movq	$0, \Z2
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	adcq	$0, \Z2
	movq	\Z3, 32+\O

	movq	16+\A, %rdx
	xorq	\Z3, \Z3
	mulx	24+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	adcq	$0, \Z3
	movq	\Z4, 40+\O
	movq	\Z5, 48+\O

	movq	24+\A, %rdx
	xorq	\Z4, \Z4
	mulx	32+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	adcq	$0, \Z4
	movq	\Z6, 56+\O
	movq	\Z7, 64+\O

	movq	32+\A, %rdx
	xorq	\Z5, \Z5
	mulx	40+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	adcq	$0, \Z5
	movq	\Z8, 72+\O
	movq	\Z9, 80+\O

	movq	40+\A, %rdx
	xorq	\Z6, \Z6
	mulx	48+\A, \T0, \T1
	adcx	\T0, \Z0
	adox	\T1, \Z1
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z1
	adox	\T1, \Z2
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	adcq	$0, \Z6
	movq	\Z0, 88+\O
	movq	\Z1, 96+\O

	movq	48+\A, %rdx
	xorq	\Z7, \Z7
	mulx	56+\A, \T0, \T1
	adcx	\T0, \Z2
	adox	\T1, \Z3
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z3
	adox	\T1, \Z4
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	adcq	$0, \Z7

	movq	56+\A, %rdx
	xorq	\Z8, \Z8
	mulx	64+\A, \T0, \T1
	adcx	\T0, \Z4
	adox	\T1, \Z5
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z5
	adox	\T1, \Z6
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	adcq	$0, \Z8

	movq	64+\A, %rdx
	xorq	\Z9, \Z9
	mulx	72+\A, \T0, \T1
	adcx	\T0, \Z6
	adox	\T1, \Z7
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z7
	adox	\T1, \Z8
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	adcq	$0, \Z9

	movq	72+\A, %rdx
	xorq	\Z0, \Z0
	mulx	80+\A, \T0, \T1
	adcx	\T0, \Z8
	adox	\T1, \Z9
	mulx	88+\A, \T0, \T1
	adcx	\T0, \Z9
	adox	\T1, \Z0
	adcq	$0, \Z0

	movq	80+\A, %rdx
	mulx	88+\A, \T0, \Z1
	addq	\T0, \Z0
	adcq	$0, \Z1

	movq	0+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	\T0, 0+\O
	xorq	\T0, \T0
	movq	8+\O, \T0
	adcx	\T0, \T0
	adox	\T1, \T0
	movq	\T0, 8+\O
	movq	8+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	16+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 16+\O
	movq	24+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 24+\O
	movq	16+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	32+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 32+\O
	movq	40+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 40+\O
	movq	24+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	48+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 48+\O
	movq	56+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 56+\O
	movq	32+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	64+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 64+\O
	movq	72+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 72+\O
	movq	40+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	80+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 80+\O
	movq	88+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 88+\O
	movq	48+\A, %rdx
	mulx	%rdx, \T0, \T1
	movq	96+\O, %rdx
	adcx	%rdx, %rdx
	adox	\T0, %rdx
	movq	%rdx, 96+\O
	adcx	\Z2, \Z2
	adox	\T1, \Z2
	movq	\Z2, 104+\O
	movq	56+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z3, \Z3
	adox	\T0, \Z3
	movq	\Z3, 112+\O
	adcx	\Z4, \Z4
	adox	\T1, \Z4
	movq	\Z4, 120+\O
	movq	64+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z5, \Z5
	adox	\T0, \Z5
	movq	\Z5, 128+\O
	adcx	\Z6, \Z6
	adox	\T1, \Z6
	movq	\Z6, 136+\O
	movq	72+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z7, \Z7
	adox	\T0, \Z7
	movq	\Z7, 144+\O
	adcx	\Z8, \Z8
	adox	\T1, \Z8
	movq	\Z8, 152+\O
	movq	80+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z9, \Z9
	adox	\T0, \Z9
	movq	\Z9, 160+\O
	adcx	\Z0, \Z0
	adox	\T1, \Z0
	movq	\Z0, 168+\O
	movq	88+\A, %rdx
	mulx	%rdx, \T0, \T1
	adcx	\Z1, \Z1
	adox	\T0, \Z1
	movq	\Z1, 176+\O
	movq	$0, %rdx
	adcx	%rdx, %rdx
	adox	\T1, %rdx
	movq	%rdx, 184+\O
.endm

.macro FP_SQR_LOW A, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, T0, T1, P, RDC, S, C
.if \RDC != 1
	SQRN	\A, 0(%rdi), \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
.else
	SQRN	\A, \S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1
	FP_RDCN_LOW	\S, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, \T1, %rsi, \P, %rdx, \C, %rdi
.endif
.endm

.macro FP_MUL_LOW A, B, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8, Z9, Z10, Z11, Z12, T0, P, RDC, C, K
#if FP_PRIME == 768
	movq	$0, \K
#endif
.if \RDC != 1
	movq	\C, \T0
	movq	\Z0, 0(\T0)
.else
	xorq	\T0, \T0
	MULRDC1	\Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z0, \K
#endif
.endif

	xorq	\T0, \T0
	movq	8+\A, %rdx
	MULADD1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z1, 8(\T0)
.else
	MULRDC1	\Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z1, \K
#endif
.endif

	xorq	\T0, \T0
	movq	16+\A, %rdx
	MULADD1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z2, 16(\T0)
.else
	MULRDC1	\Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z2, \K
#endif
.endif

	xorq	\T0, \T0
	movq	24+\A, %rdx
	MULADD1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z3, 24(\T0)
.else
	MULRDC1	\Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z3, \K
#endif
.endif

	xorq	\T0, \T0
	movq	32+\A, %rdx
	MULADD1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z4, 32(\T0)
.else
	MULRDC1	\Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z4, \K
#endif
.endif

	xorq	\T0, \T0
	movq	40+\A, %rdx
	MULADD1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z5, 40(\T0)
.else
	MULRDC1	\Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z5, \K
#endif
.endif

	xorq	\T0, \T0
	movq	48+\A, %rdx
	MULADD1	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z6, 48(\T0)
.else
	MULRDC1	\Z6, \Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z6, \K
#endif
.endif

	xorq	\T0, \T0
	movq	56+\A, %rdx
	MULADD1	\Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z7, 56(\T0)
.else
	MULRDC1	\Z7, \Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z7, \K
#endif
.endif

	xorq	\T0, \T0
	movq	64+\A, %rdx
	MULADD1	\Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z8, 64(\T0)
.else
	MULRDC1	\Z8, \Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z8, \K
#endif
.endif

	xorq	\T0, \T0
	movq	72+\A, %rdx
	MULADD1	\Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z9, 72(\T0)
.else
	MULRDC1	\Z9, \Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z9, \K
#endif
.endif

	xorq	\T0, \T0
	movq	80+\A, %rdx
	MULADD1	\Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z10, 80(\T0)
.else
	MULRDC1	\Z10, \Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \T0, zero(%rip), \P
#if FP_PRIME == 768
	movq	\Z10, \K
#endif
.endif

	xorq	\T0, \T0
	movq	88+\A, %rdx
	MULADD1	\Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, zero(%rip), \B, \K
.if \RDC != 1
	movq	\C, \T0
	movq	\Z11, 88(\T0)
.else
	MULRDC1	\Z11, \Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, \T0, zero(%rip), \P
.endif

.if \RDC != 1
	movq	\C, \T0
	movq	\Z12, 96(\T0)
	movq	\Z0, 104(\T0)
	movq	\Z1, 112(\T0)
	movq	\Z2, 120(\T0)
	movq	\Z3, 128(\T0)
	movq	\Z4, 136(\T0)
	movq	\Z5, 144(\T0)
	movq	\Z6, 152(\T0)
	movq	\Z7, 160(\T0)
	movq	\Z8, 168(\T0)
	movq	\Z9, 176(\T0)
	movq	\Z10, 184(\T0)
.else
	movq	\C, \T0
	FINALC	\Z12, \Z0, \Z1, \Z2, \Z3, \Z4, \Z5, \Z6, \Z7, \Z8, \Z9, \Z10, %rdx, 0(\T0), \Z11
.endif
.endm
