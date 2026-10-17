#!/usr/bin/env python3
"""Generates the x64-asm-Nl backend sources in the design of x64-asm-12l.

Usage: tools/relic-gen-x64.py N OUTDIR

It writes macro.s and the assembly files of the backend for N limbs. The C
files and CMakeLists.txt are generic and can be copied from x64-asm-12l. The
supported primes come from PRIMES below; 12 limbs reproduces x64-asm-12l.
Check a new backend with tools/relic-check-fp.c.
"""

import os
import sys

# Primes per limb count: (FP_PRIME, hex of p, comment or None).
PRIMES = {
	12: [
		(768, ("FFFFFFE4FF4001423290395E476657BA172EC88A91CFC7D2BA1AF14A"
			"9BC88DBA6A6D9D80470079AE9AD532EA851862BD828EC90E320E3793"
			"31B6221831F61A721429BCDA53E20A8F9FBEDDEE98705380ACE2A128"
			"43C534B1591ADE1200800001"), None),
		(766, ("3FFFB8002607F379C2E122127943E41E89F38FC6E7249EF167D35D38"
			"9C7BD43CDC0F8D8300A6748A4C8C62B406D882C8A2902CAC0A117EAD"
			"04A837318C7897B6C81A3A94170A2E5A211730168CD3106CFCBC4220"
			"020A6592F45D1E791E054605"),
				"AFG16-766, the prime picked for 766 bits. K16_766 is not "
					"supported."),
		(765, ("166A30BEAF4CE221BC5664C6F237BCB4D4A66E04AA631EEA1629227B"
			"B6527E4EFE00400021385D1A7071D6BA0697D5A12C9088558A226AF0"
			"93D3AA2586A9BB7B0140000000000000000000000000000000000000"
			"38223FF01000EFC080000001"), "FM16-765"),
	],
	11: [
		(672, ("9401FF90F28BFFB0C610FB10BF9E0FEFD59211629A7991563C5E468D"
			"43EC9CFE1549FD59C20AB5B9A7CDA7F27A0067B8303EEB4B31555CF4"
			"F24050ED155555CD7FA7A5F8AAAAAAAD47EDE1A6AAAAAAAAB69E6DCB"),
				"CP6-672, the Cocks-Pinch prime with embedding degree 6."),
	],
}

REGS = ["%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
	"%rbx", "%rbp", "%rcx", "%rsi", "%rdi"]


def zs(n, prefix="Z"):
	return ", ".join("%s%d" % (prefix, i) for i in range(n))


def bz(names):
	return ", ".join("\\" + x for x in names)


def consts(p):
	"""Returns the limbs, U0 and the constants of fp_mul1_low for p."""
	n = (p.bit_length() + 63) // 64
	limbs = [(p >> (64 * i)) & ((1 << 64) - 1) for i in range(n)]
	u0 = (-pow(p, -1, 1 << 64)) % (1 << 64)
	s = p.bit_length() - 1
	bar = (1 << (p.bit_length() + 63)) // p
	assert bar < (1 << 64)
	return limbs, u0, bar, s % 64, s // 64

# The license header, shared by all files but for the year.
LICENSE = '''/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) %s RELIC Authors
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
'''

# The year and the documentation after the license in each file.
DOCS = {
	'macro.s': ('2023', '''
#include "relic_fp_low.h"

/**
 * @file
 *
 * Implementation of low-level prime field multiplication.
 *
 * @ingroup fp
 */

'''),
	'relic_fp_add_low.s': ('2023', '''
/**
 * @file
 *
 * Implementation of the low-level prime field addition and subtraction
 * functions.
 *
 * @ingroup fp
 */
'''),
	'relic_fp_mul_low.s': ('2023', '''
/**
 * @file
 *
 * Implementation of the low-level prime field multiplication functions.
 *
 * @ingroup bn
 */
'''),
	'relic_fp_rdc_low.s': ('2023', '''
/**
 * @file
 *
 * Implementation of low-level prime field modular reduction.
 *
 * @ingroup fp
 */
'''),
	'relic_fp_sqr_low.s': ('2023', '''
/**
 * @file
 *
 * Implementation of the low-level prime field squaring functions.
 *
 * @ingroup fp
 */
'''),
	'relic_fp_shift_low.s': ('2021', '''
/**
 * @file
 *
 * Implementation of the low-level prime field shifting functions.
 *
 * @ingroup fp
 */
'''),
}

# The macros for addition and subtraction with carries.
SMALL = '''.macro ADD1 i j
	movq	8*\\i(%rsi), %r10
	adcq	$0, %r10
	movq	%r10, 8*\\i(%rdi)
	.if \\i - \\j
		ADD1 "(\\i + 1)" \\j
	.endif
.endm

.macro ADDN i j
	movq	8*\\i(%rdx), %r11
	adcq	8*\\i(%rsi), %r11
	movq	%r11, 8*\\i(%rdi)
	.if \\i - \\j
		ADDN "(\\i + 1)" \\j
	.endif
.endm

.macro SUB1 i j
	movq	8*\\i(%rsi),%r10
	sbbq	$0, %r10
	movq	%r10,8*\\i(%rdi)
	.if \\i - \\j
		SUB1 "(\\i + 1)" \\j
	.endif
.endm

.macro SUBN i j
	movq	8*\\i(%rsi), %r8
	sbbq	8*\\i(%rdx), %r8
	movq	%r8, 8*\\i(%rdi)
	.if \\i - \\j
		SUBN "(\\i + 1)" \\j
	.endif
.endm

.macro DBLN i j
	movq	8*\\i(%rsi), %r8
	adcq	%r8, %r8
	movq	%r8, 8*\\i(%rdi)
	.if \\i - \\j
		DBLN "(\\i + 1)" \\j
	.endif
.endm

'''


class Gen:
	def __init__(self, n, full):
		self.n = n
		# Whether some supported prime fills the top bit of the top limb.
		self.full = full
		self.top = 64 * n

	def iffull(self):
		return "#if FP_PRIME == %d" % self.top

	# ---------------------------------------------------------------- macro.s
	def mulm(self):
		n = self.n
		o = ["// [Z0:Z%d] <- a0 x b, with a pointer to a in A." % n,
			".macro MULM A, B, %s, T" % zs(n + 1),
			"\tmovq\t\\A, %rdx",
			"\tmovq\t0(%rdx), %rdx",
			"\tmulx\t0+\\B, \\Z0, \\Z1",
			"\txorq\t\\T, \\T"]
		for i in range(1, n):
			o.append("\tmulx\t%d+\\B, \\T, \\Z%d" % (8 * i, i + 1))
			o.append("\tadox\t\\T, \\Z%d" % i)
		o.append("\tadox\tZEROS, \\Z%d" % n)
		o.append(".endm")
		return o

	def muladd(self):
		n = self.n
		o = ["// [Z0:Z%d, X] <- [Z0:Z%d, CARRY] + rdx x M, where the free "
			"register X turns into" % (n - 1, n - 1),
			"// the top word and CARRY is zero unless the prime fills the top "
				"bit.",
			"// Needs CF = OF = 0 on entry.",
			".macro MULADD %s, X, T, M" % zs(n),
			"\tmulx\t0+\\M, \\T, \\X",
			"\tadox\t\\T, \\Z0",
			"\tadox\t\\X, \\Z1"]
		for i in range(1, n):
			o.append("\tmulx\t%d+\\M, \\T, \\X" % (8 * i))
			o.append("\tadcx\t\\T, \\Z%d" % i)
			if i < n - 1:
				o.append("\tadox\t\\X, \\Z%d" % (i + 1))
		o.append("\tadox\tZEROS, \\X")
		o.append("\tadcx\tCARRY, \\X")
		o.append(".endm")
		return o

	def mulrdc(self):
		n = self.n
		o = ["// [Z1:Z%d] <- ([Z0:Z%d] + (Z0 x U0 mod 2^64) x M) / 2^64, "
			"freeing Z0. The low" % (n, n),
			"// word cancels, so its carry is Z0 != 0, which adding all-ones "
				"to Z0 yields.",
			"// With Z%d blank, the top word is zero on entry and is left in "
				"Z0." % n,
			"// Needs CF = OF = 0 on entry.",
			".macro MULRDC %s, T, M" % zs(n + 1),
			"\tmovq\t$U0, %rdx",
			"\tmulx\t\\Z0, %rdx, \\T",
			"\tmulx\t0+\\M, \\T, \\T",
			"\tadcx\tONES, \\Z0",
			"\tadox\t\\T, \\Z1"]
		for i in range(1, n):
			o.append("\tmulx\t%d+\\M, \\T, \\Z0" % (8 * i))
			o.append("\tadcx\t\\T, \\Z%d" % i)
			if i < n - 1:
				o.append("\tadox\t\\Z0, \\Z%d" % (i + 1))
		o += [".ifb \\Z%d" % n,
			"\tadox\tZEROS, \\Z0",
			"\tadcx\tZEROS, \\Z0",
			".else",
			"\tadox\t\\Z0, \\Z%d" % n,
			"\tadcx\tZEROS, \\Z%d" % n,
			".endif",
			".endm"]
		return o

	def finalc(self):
		n = self.n
		o = ["// Final correction: stores [C:Z0:Z%d] - p if it does not borrow "
			"and [Z0:Z%d]" % (n - 1, n - 1),
			"// otherwise at the pointer in CPTR. C is blank when the input is "
				"below 2^%d." % self.top,
			".macro FINALC %s, C" % zs(n),
			"\tmovq\tCPTR, %rdx"]
		for i in range(n):
			o.append("\tmovq\t\\Z%d, %d(%%rdx)" % (i, 8 * i))
		o.append("\tsubq\tp0(%rip), \\Z0")
		for i in range(1, n):
			o.append("\tsbbq\tp%d(%%rip), \\Z%d" % (i, i))
		o += [".ifnb \\C", "\tsbbq\t$0, \\C", ".endif"]
		for i in range(n):
			o.append("\tcmovc\t%d(%%rdx), \\Z%d" % (8 * i, i))
		for i in range(n):
			o.append("\tmovq\t\\Z%d, %d(%%rdx)" % (i, 8 * i))
		o.append(".endm")
		return o

	def rdcn(self):
		n = self.n
		words = {12: "twelve", 11: "eleven", 10: "ten"}[n]
		o = ["// [Z0:Z%d] <- [Z0:Z%d]/2^%d mod p, at most p, by %s Montgomery "
			"steps." % (n - 1, n - 1, self.top, words),
			"// Needs CF = OF = 0 on entry.",
			".macro RDCN %s, T, P" % zs(n)]
		for k in range(n):
			rot = ["Z%d" % ((k + i) % n) for i in range(n)]
			o.append("\tMULRDC\t%s, , \\T, \\P" % bz(rot))
		o.append(".endm")
		return o

	def addh(self):
		n = self.n
		o = ["// [Z0:Z%d] += [0+H:%d+H]." % (n - 1, 8 * (n - 1)),
			".macro ADDH %s, H" % zs(n),
			"\taddq\t0+\\H, \\Z0"]
		for i in range(1, n):
			o.append("\tadcq\t%d+\\H, \\Z%d" % (8 * i, i))
		o.append(".endm")
		return o

	def fp_rdcn_low(self):
		n = self.n
		z = bz(["Z%d" % i for i in range(n)])
		o = ["// c <- a/2^%d mod p for a = 0+A < pR, with c at the pointer in "
			"CPTR: reduce" % self.top,
			"// the low half to at most p, add the high half, which is below "
				"p, and subtract",
			"// p once. The low half stays below 2^%d at each step, so no "
				"carry leaves the" % self.top]
		if self.full:
			o.append("// accumulator. For %d bits the sum can reach 2^%d and "
				"its carry goes to T." % (self.top, self.top))
		else:
			o.append("// accumulator.")
		o += ["// A must not be based on Z0..Z%d or T." % (n - 1),
			".macro FP_RDCN_LOW A, %s, T, P" % zs(n),
			"\txorq\t\\T, \\T"]
		o.append("\tmovq\t0+\\A, \\Z0")
		for i in range(1, n):
			o.append("\tmovq\t%d+\\A, \\Z%d" % (8 * i, i))
		o.append("\tRDCN\t%s, \\T, \\P" % z)
		o.append("\tADDH\t%s, %d+\\A" % (z, 8 * n))
		if self.full:
			o += [self.iffull(), "\tmovq\t$0, \\T", "\tadcq\t$0, \\T",
				"\tFINALC\t%s, \\T" % z, "#else", "\tFINALC\t%s" % z, "#endif"]
		else:
			o.append("\tFINALC\t%s" % z)
		o.append(".endm")
		return o

	def sqrn(self):
		n = self.n
		o = ["// a^2 for a = 0+A, computing each cross product once, with A "
			"and O based on",
			"// %%rsp. With RDC = 0, the %d words of a^2 go to the pointer in "
				"CPTR. With" % (2 * n),
			"// RDC = 1, the low %s words stay in [Z0:Z%d] and the high %s go "
				"to" % (self.word(n), n - 1, self.word(n)),
			"// %d+O. O is %d words of scratch." % (8 * n, 2 * n),
			".macro SQRN A, O, %s, T0, T1, RDC" % zs(n),
			"\t// The cross products a_i x a_j for i < j go to words 1..%d of "
				"O. Word w" % (2 * n - 2),
			"\t// accumulates in Z(w mod %d) and is stored once no later row "
				"adds to it." % n,
			"\t// [Z1:Z%d, Z0] <- a0 x [a1:a%d]" % (n - 1, n - 1),
			"\tmovq\t0+\\A, %rdx",
			"\tmulx\t8+\\A, \\Z1, \\Z2"]
		for j in range(2, n):
			o.append("\tmulx\t%d+\\A, \\T0, \\Z%d" % (8 * j, (j + 1) % n))
			o.append("\t%s\t\\T0, \\Z%d" % ("addq" if j == 2 else "adcq", j))
		o.append("\tadcq\t$0, \\Z0")
		o.append("\tmovq\t\\Z1, 8+\\O")
		o.append("\tmovq\t\\Z2, 16+\\O")
		for i in range(1, n - 1):
			o.append("")
			o.append("\t// words %d..%d += a%d x "
				"[a%d:a%d]" % (2 * i + 1, n + i, i, i + 1, n - 1))
			o.append("\tmovq\t%d+\\A, %%rdx" % (8 * i))
			o.append("\txorq\t\\Z%d, \\Z%d" % (i, i))
			for j in range(i + 1, n):
				o.append("\tmulx\t%d+\\A, \\T0, \\T1" % (8 * j))
				o.append("\tadcx\t\\T0, \\Z%d" % ((i + j) % n))
				o.append("\tadox\t\\T1, \\Z%d" % ((i + j + 1) % n))
			o.append("\tadcq\t$0, \\Z%d" % i)
			o.append("\tmovq\t\\Z%d, "
				"%d+\\O" % ((2 * i + 1) % n, 8 * (2 * i + 1)))
			o.append("\tmovq\t\\Z%d, "
				"%d+\\O" % ((2 * i + 2) % n, 8 * (2 * i + 2)))
		o += ["",
			"\t// Doubles the cross products and adds the squares a_k^2 at "
				"word 2k, word by",
			"\t// word, with CF carrying the doubling and OF the squares. %rdx "
				"takes each",
			"\t// word that is stored.",
			"\tmovq\t0+\\A, %rdx",
			"\tmulx\t%rdx, \\T0, \\T1",
			".if \\RDC != 1",
			"\tmovq\tCPTR, \\Z0",
			"\tmovq\t\\T0, 0(\\Z0)",
			".else",
			"\tmovq\t\\T0, \\Z0",
			".endif",
			"\txorq\t%rdx, %rdx",
			".if \\RDC != 1"]
		o += self.sqr_double(False)
		o.append(".else")
		o += self.sqr_double(True)
		o += [".endif", "", ".endm"]
		return o

	def word(self, n):
		return {12: "twelve", 11: "eleven", 10: "ten"}[n]

	def sqr_double(self, rdc):
		n = self.n
		o = []
		for w in range(1, 2 * n):
			if w % 2 == 0:
				o.append("\tmovq\t%d+\\A, %%rdx" % (4 * w))
				o.append("\tmulx\t%rdx, \\T0, \\T1")
			t = "\\T0" if w % 2 == 0 else "\\T1"
			if rdc and w < n:
				o.append("\tmovq\t%d+\\O, \\Z%d" % (8 * w, w))
				o.append("\tadcx\t\\Z%d, \\Z%d" % (w, w))
				o.append("\tadox\t%s, \\Z%d" % (t, w))
				continue
			if w == 2 * n - 1:
				o.append("\tmovq\t$0, %rdx")
			else:
				o.append("\tmovq\t%d+\\O, %%rdx" % (8 * w))
			o.append("\tadcx\t%rdx, %rdx")
			o.append("\tadox\t%s, %%rdx" % t)
			if rdc:
				o.append("\tmovq\t%%rdx, %d+\\O" % (8 * w))
			else:
				o.append("\tmovq\t%%rdx, %d(\\Z0)" % (8 * w))
		return o

	def fp_sqr_low(self):
		n = self.n
		z = bz(["Z%d" % i for i in range(n)])
		o = ["// c <- a^2 (RDC = 0) or a^2/2^%d mod p (RDC = 1) for a = 0+A, "
			"with c at the" % self.top,
			"// pointer in CPTR and a^2 < pR when RDC = 1. A and O are as in "
				"SQRN.",
			".macro FP_SQR_LOW A, O, %s, T0, T1, P, RDC" % zs(n),
			"\tSQRN\t\\A, \\O, %s, \\T0, \\T1, \\RDC" % z,
			".if \\RDC == 1",
			"\t// The low half reduces to at most p and the high half is below "
				"p.",
			"\txorq\t\\T0, \\T0",
			"\tRDCN\t%s, \\T0, \\P" % z,
			"\tADDH\t%s, %d+\\O" % (z, 8 * n)]
		if self.full:
			o += [self.iffull(), "\tmovq\t$0, \\T0", "\tadcq\t$0, \\T0",
				"\tFINALC\t%s, \\T0" % z, "#else", "\tFINALC\t%s" % z, "#endif"]
		else:
			o.append("\tFINALC\t%s" % z)
		o += [".endif", ".endm"]
		return o

	def fp_mul_low(self):
		n = self.n
		o = ["// Interleaved Montgomery multiplication after MULM, rotating "
			"the accumulator",
			"// over Z0..Z%d. With RDC = 0, it stores the double-precision "
				"product instead." % n,
			".macro FP_MUL_LOW A, B, %s, T, P, RDC" % zs(n + 1)]
		for i in range(n):
			rot = ["Z%d" % ((i + k) % (n + 1)) for k in range(n + 1)]
			if i > 0:
				o.append("")
				o.append("\t// z += a%d x b" % i)
				o.append("\tmovq\t\\A, %rdx")
				o.append("\tmovq\t%d(%%rdx), %%rdx" % (8 * i))
				o.append("\txorq\t\\T, \\T")
				o.append("\tMULADD\t%s, \\T, \\B" % bz(rot[:n] + [rot[n]]))
				o.append("")
			o.append(".if \\RDC != 1")
			o.append("\tmovq\tCPTR, %rdx")
			o.append("\tmovq\t\\%s, %d(%%rdx)" % (rot[0], 8 * i))
			o.append(".else")
			o.append("\t// z = (z + (z0 x u0 mod 2^64) x p) / 2^64")
			o.append("\tMULRDC\t%s, \\T, \\P" % bz(rot))
			if self.full:
				o.append(self.iffull())
				o.append("\t// The sum can reach 2^(64 * %d), so keep its "
					"carry." % (n + 1))
				o.append("\tmovq\t$0, \\%s" % rot[0])
				o.append("\tadox\tZEROS, \\%s" % rot[0])
				o.append("\tadcx\tZEROS, \\%s" % rot[0])
				if i < n - 1:
					o.append("\tmovq\t\\%s, CARRY" % rot[0])
				o.append("#endif")
			o.append(".endif")
		# The product ends with the accumulator rotated by n.
		rot = ["Z%d" % ((n + k) % (n + 1)) for k in range(n + 1)]
		o.append("")
		o.append(".if \\RDC != 1")
		for k in range(n):
			o.append("\tmovq\t\\%s, %d(%%rdx)" % (rot[k], 8 * (n + k)))
		o.append(".else")
		if self.full:
			o.append(self.iffull())
			o.append("\tFINALC\t%s" % bz(rot))
			o.append("#else")
			o.append("\tFINALC\t%s" % bz(rot[:n]))
			o.append("#endif")
		else:
			o.append("\tFINALC\t%s" % bz(rot[:n]))
		o += [".endif", ".endm"]
		return o


def main():
	n = int(sys.argv[1])
	out = sys.argv[2]
	g = Gen(n, any(b == 64 * n for b, _, _ in PRIMES[n]))
	head = header("macro.s")
	b = []
	names = []
	for k, (bits, h, note) in enumerate(PRIMES[n]):
		limbs, u0, bar, bars, barj = consts(int(h, 16))
		assert len(limbs) == n
		b.append(("#if" if k == 0 else "#elif") + " FP_PRIME == %d" % bits)
		if note:
			b.append("/* %s */" % note)
		for i, l in enumerate(limbs):
			b.append("#define P%d\t0x%016X" % (i, l))
		b.append("#define U0\t0x%016X" % u0)
		b.append("#define BAR\t0x%016X" % bar)
		b.append("#define BARS\t%d" % bars)
		b.append("#define BARJ\t%d" % barj)
		names.append(str(bits))
	b.append("#else")
	names.sort(key=int)
	last = names[-1]
	if len(names) > 1:
		last = ", ".join(names[:-1]) + " or " + last
	b.append('#error "x64-asm-%dl supports only FP_PRIME = %s."' % (n, last))
	b.append("#endif")
	blocks = "\n".join(b) + "\n\n"
	frame = 8 * n
	tail = """#if defined(__APPLE__)
#define cdecl(S) _cdecl(S)
#define _cdecl(S) _ ## S
#else
#define cdecl(S) S
#endif

#if defined(__ELF__)
.section .note.GNU-stack, "", %progbits
#endif

/*
 * Stack frame of the multiplication and reduction functions. With {w} digits,
 * the accumulator takes {acc} registers, the multiplier takes rdx and one more
 * register is left for the partial products, so the operand b, the pointers
 * and the constants live on the stack.
 */
#define BCPY	0(%rsp)
#define APTR	{a}(%rsp)
#define CPTR	{c}(%rsp)
#define ZEROS	{z}(%rsp)
#define ONES	{o}(%rsp)
#define CARRY	{k}(%rsp)
#define FRAME	{f}
/* The squaring functions also keep the {w2} words of a^2 on the stack. */
#define SBUF	{f}(%rsp)
#define SFRAME	{sf}

.text
""".format(w=n, acc=n + 1, a=frame, c=frame + 8, z=frame + 16,
		o=frame + 24, k=frame + 32, f=frame + 40, w2=2 * n,
		sf=frame + 40 + 16 * n)
	small = SMALL
	body = []
	for part in (g.mulm(), g.muladd(), g.mulrdc(), g.finalc(), g.rdcn(),
			g.addh(), g.fp_rdcn_low(), g.sqrn(), g.fp_sqr_low(),
				g.fp_mul_low()):
		body.append("\n".join(part))
	text = head + blocks + tail + "\n" + small + "\n\n".join(body) + "\n"
	os.makedirs(out, exist_ok=True)
	open(os.path.join(out, "macro.s"), "w").write(text)
	write_all(g, out)


# ------------------------------------------------------------------ other files
ACC = ["%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "%rax",
	"%rbx", "%rbp", "%rcx"]
PUSH6 = ["\tpush\t%rbx", "\tpush\t%rbp", "\tpush\t%r12", "\tpush\t%r13",
	"\tpush\t%r14", "\tpush\t%r15", ""]
POP6 = ["\tpop\t\t%r15", "\tpop\t\t%r14", "\tpop\t\t%r13", "\tpop\t\t%r12",
	"\tpop\t\t%rbp", "\tpop\t\t%rbx", "\tret"]
PUSHM = ["\tpush\t%r12", "\tpush\t%r13", "\tpush\t%r14", "\tpush\t%r15",
	"\tpush\t%rbx", "\tpush\t%rbp"]
POPM = ["\tpop\t\t%rbp", "\tpop\t\t%rbx", "\tpop\t\t%r15", "\tpop\t\t%r14",
	"\tpop\t\t%r13", "\tpop\t\t%r12", "\tret"]


def header(name):
	year, doc = DOCS[name]
	return LICENSE % year + doc


def add_low(g):
	n = g.n
	r = ACC[:n]
	full = g.full
	o = ['#include "relic_fp_low.h"', '#include "macro.s"', "",
		"#if defined(__APPLE__)", ".section __TEXT,__const", "#else",
		".section .rodata", "#endif", "", ".p2align 3"]
	o += ["p%d: .quad P%d" % (i, i) for i in range(n)] + [""]
	o += [".global "
		"p%d" % i for i in range(n)] + ["", "#if RLC_OPSYS != RLC_WINDOWS", ""]
	o += [".hidden p%d" % i for i in range(n)] + ["", "#endif", "", ".text", ""]
	fns = ["add1", "addn", "addm", "addd", "addc", "sub1", "subn", "subm",
		"subd", "subc", "negm", "dbln", "dblm", "hlvm", "hlvd"]
	o += [".global cdecl(fp_%s_low)" % f for f in fns] + [""]

	def keep_carry():
		if not full:
			return []
		return [g.iffull(),
			"\t// p fills the top bit, so keep the carry of the sum.",
			"\tmovq\t$0, %rsi", "\tadcq\t$0, %rsi", "#endif"]

	def correct(base):
		"""Subtracts p from [rsi:r] at base(%rdi), keeping it if no borrow."""
		s = []
		for i in range(n):
			s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
		s.append("\tsubq\tp0(%%rip), %s" % r[0])
		for i in range(1, n):
			s.append("\tsbbq\tp%d(%%rip), %s" % (i, r[i]))
		if full:
			s += [g.iffull(), "\tsbbq\t$0, %rsi", "#endif"]
		for i in range(n):
			s.append("\tcmovc\t%d(%%rdi), %s" % (base + 8 * i, r[i]))
		for i in range(n):
			s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
		return s

	def addback(base):
		"""Adds p to the difference at base(%rdi) if it borrowed."""
		s = ["", "\tsbbq\t%rsi, %rsi"]
		for i in range(n):
			s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
		for i in range(n):
			s.append("\tmovq\tp%d(%%rip), %s" % (i, r[i]))
			s.append("\tandq\t%%rsi, %s" % r[i])
		s.append("\taddq\t%d(%%rdi), %s" % (base, r[0]))
		for i in range(1, n):
			s.append("\tadcq\t%d(%%rdi), %s" % (base + 8 * i, r[i]))
		for i in range(n):
			s.append("\tmovq\t%s, %d(%%rdi)" % (r[i], base + 8 * i))
		return s

	# fp_add1_low and fp_addn_low
	o += ["cdecl(fp_add1_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r10",
		"\taddq\t%rdx, %r10", "\tmovq\t%r10, 0(%rdi)", "",
		"\tADD1 1 (RLC_FP_DIGS - 1)", "\tadcq\t$0, %rax", "", "\tret", ""]
	o += ["cdecl(fp_addn_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rdx), %r11",
		"\taddq\t0(%rsi), %r11", "\tmovq\t%r11, 0(%rdi)", "",
		"\tADDN\t1 (RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "", "\tret", ""]
	# fp_addm_low
	o += ["cdecl(fp_addm_low):"] + PUSH6
	o.append("\tmovq\t0(%%rdx), %s" % r[0])
	o.append("\taddq\t0(%%rsi), %s" % r[0])
	for i in range(1, n):
		o.append("\tmovq\t%d(%%rdx), %s" % (8 * i, r[i]))
		o.append("\tadcq\t%d(%%rsi), %s" % (8 * i, r[i]))
	o += keep_carry() + [""] + correct(0) + [""] + POP6 + [""]
	# fp_addd_low
	o += ["cdecl(fp_addd_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rdx), %r11",
		"\taddq\t0(%rsi), %r11", "\tmovq\t%r11, 0(%rdi)", "",
		"\tADDN\t1 (2 * RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "\tret", ""]
	# fp_addc_low
	o += ["cdecl(fp_addc_low):"] + PUSH6
	o += ["\tmovq\t0(%rdx), "
		"%r11", "\taddq\t0(%rsi), %r11", "\tmovq\t%r11, 0(%rdi)", "",
		"\tADDN\t1 (RLC_FP_DIGS - 1)", ""]
	for i in range(n):
		o.append("\tmovq\t%d(%%rdx), %s" % (8 * (n + i), r[i]))
		o.append("\tadcq\t%d(%%rsi), %s" % (8 * (n + i), r[i]))
	o += keep_carry() + [""] + correct(8 * n) + [""] + POP6 + [""]
	# fp_sub1_low and fp_subn_low
	o += ["cdecl(fp_sub1_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r10",
		"\tsubq\t%rdx, %r10", "\tmovq\t%r10, 0(%rdi)", "",
		"\tSUB1\t1 (RLC_FP_DIGS - 1)", "\tadcq\t$0, %rax", "", "\tret", ""]
	o += ["cdecl(fp_subn_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r11",
		"\tsubq\t0(%rdx), %r11", "\tmovq\t%r11, 0(%rdi)", "",
		"\tSUBN\t1 (RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "", "\tret", ""]
	# fp_subm_low
	o += ["cdecl(fp_subm_low):"] + PUSH6
	o.append("\tmovq\t0(%%rsi), %s" % r[0])
	o.append("\tsubq\t0(%%rdx), %s" % r[0])
	for i in range(1, n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, r[i]))
		o.append("\tsbbq\t%d(%%rdx), %s" % (8 * i, r[i]))
	o += addback(0) + [""] + POP6 + [""]
	# fp_subd_low
	o += ["cdecl(fp_subd_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r8",
		"\tsubq\t0(%rdx), %r8", "\tmovq\t%r8, 0(%rdi)", "",
		"\tSUBN\t1 (2 * RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "\tret", ""]
	# fp_subc_low
	o += ["cdecl(fp_subc_low):"] + PUSH6
	o += ["\tmovq\t0(%rsi), "
		"%r8", "\tsubq\t0(%rdx), %r8", "\tmovq\t%r8, 0(%rdi)", "",
		"\tSUBN\t1 (RLC_FP_DIGS - 1)", ""]
	for i in range(n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * (n + i), r[i]))
		o.append("\tsbbq\t%d(%%rdx), %s" % (8 * (n + i), r[i]))
	o += addback(8 * n) + [""] + POP6 + [""]
	# fp_negm_low: c = p - a if a != 0, else 0.
	o += ["cdecl(fp_negm_low):"] + PUSH6
	for i in range(1, n):
		o.append("\txorq\t%s, %s" % (r[i], r[i]))
	o.append("\tmovq\t0(%%rsi), %s" % r[0])
	for i in range(1, n):
		o.append("\torq\t%d(%%rsi), %s" % (8 * i, r[0]))
	o.append("\ttestq\t%s, %s" % (r[0], r[0]))
	for i in range(n):
		o.append("\tcmovnz\tp%d(%%rip), %s" % (i, r[i]))
	o.append("\tsubq\t0(%%rsi), %s" % r[0])
	o.append("\tmovq\t%s, 0(%%rdi)" % r[0])
	for i in range(1, n):
		o.append("\tsbbq\t%d(%%rsi), %s" % (8 * i, r[i]))
		o.append("\tmovq\t%s, %d(%%rdi)" % (r[i], 8 * i))
	o += [""] + POP6 + [""]
	# fp_dbln_low
	o += ["cdecl(fp_dbln_low):", "\txorq\t%rax, %rax", "\tmovq\t0(%rsi), %r8",
		"\taddq\t%r8, %r8", "\tmovq\t%r8, 0(%rdi)", "",
		"\tDBLN 1 (RLC_FP_DIGS - 1)", "", "\tadcq\t$0, %rax", "\tret", ""]
	# fp_dblm_low
	o += ["cdecl(fp_dblm_low):"] + PUSH6
	o.append("\tmovq\t0(%%rsi), %s" % r[0])
	o.append("\taddq\t%s, %s" % (r[0], r[0]))
	for i in range(1, n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, r[i]))
		o.append("\tadcq\t%s, %s" % (r[i], r[i]))
	o += keep_carry() + [""] + correct(0) + [""] + POP6 + [""]
	# fp_hlvm_low: c = (a + (a odd ? p : 0)) / 2, with the carry shifted in.
	h = ["%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15", "%rbp",
		"%rbx", "%rcx", "%rax"][:n]
	o += ["cdecl(fp_hlvm_low):"] + PUSHM + ["",
		"\tmovq\t$1, %rdx", "\tandq\t0(%rsi), %rdx", "\tmovq\t$0, %rdx"]
	for i in range(n):
		o.append("\tmovq\t$P%d, %s" % (i, h[i]))
	for i in range(n):
		o.append("\tcmovz\t%%rdx, %s" % h[i])
	o.append("")
	o.append("\taddq\t0(%%rsi), %s" % h[0])
	for i in range(1, n):
		o.append("\tadcq\t%d(%%rsi), %s" % (8 * i, h[i]))
	o.append("")
	for i in reversed(range(n)):
		o.append("\trcrq\t$1, %s" % h[i])
	o.append("")
	for i in range(n):
		o.append("\tmovq\t%s, %d(%%rdi)" % (h[i], 8 * i))
	o += ["\txorq\t%rax, %rax", ""] + POPM + [""]
	# fp_hlvd_low: the same over 2n digits, adding p to the low half.
	o += ["cdecl(fp_hlvd_low):"] + PUSHM + ["",
		"\tmovq\t$1, %rdx", "\tandq\t0(%rsi), %rdx", "\tmovq\t$0, %rdx"]
	for i in range(n):
		o.append("\tmovq\t$P%d, %s" % (i, h[i]))
	for i in range(n):
		o.append("\tcmovz\t%%rdx, %s" % h[i])
	o.append("")
	o.append("\taddq\t0(%%rsi), %s" % h[0])
	for i in range(1, n):
		o.append("\tadcq\t%d(%%rsi), %s" % (8 * i, h[i]))
	for i in range(n):
		o.append("\tmovq\t%d(%%rsi), %%rdx" % (8 * (n + i)))
		o.append("\tadcq\t$0, %rdx")
		o.append("\tmovq\t%%rdx, %d(%%rdi)" % (8 * (n + i)))
	o.append("")
	for i in reversed(range(n)):
		o.append("\trcrq\t$1, %d(%%rdi)" % (8 * (n + i)))
	for i in reversed(range(n)):
		o.append("\trcrq\t$1, %s" % h[i])
	o.append("")
	for i in range(n):
		o.append("\tmovq\t%s, %d(%%rdi)" % (h[i], 8 * i))
	o += [""] + POPM
	return o


def mul_low(g):
	n = g.n
	o = ['#include "macro.s"', "", ".text", "",
		".global cdecl(fp_mul1_low)", ".global cdecl(fp_muln_low)",
		".global cdecl(fp_mulm_low)", "",
		"/*", " * Function: fp_mul1_low",
		" * Inputs: rdi = c, rsi = a, rdx = digit < 2^63",
		" * Output: c = a * digit mod p, in constant time", " */",
		"cdecl(fp_mul1_low):", "\tpush\t%rbx",
			"\tsubq\t$%d, %%rsp" % (16 * (n + 1)), "",
		"\t/* d = a * digit. */"]
	t = 8 * (n + 1)
	for i in range(n):
		hi = "%r8" if i % 2 == 0 else "%r9"
		o.append("\tmulxq\t%d(%%rsi), %%rax, %s" % (8 * i, hi))
		if i > 0:
			o.append("\t%s\t%s, %%rax" % ("addq" if i == 1 else "adcq",
				"%r8" if i % 2 == 1 else "%r9"))
		o.append("\tmovq\t%%rax, %d(%%rsp)" % (8 * i))
	last = "%r8" if (n - 1) % 2 == 0 else "%r9"
	o.append("\tadcq\t$0, %s" % last)
	o.append("\tmovq\t%s, %d(%%rsp)" % (last, 8 * n))
	o += ["",
		"\t/* q = floor(floor(d / 2^(|p| - 1)) * BAR / 2^64) is at most 2 "
			"below",
		"\t * floor(d / p). */", "\tmovq\t(8 * BARJ)(%rsp), %rax",
		"\tmovq\t(8 * BARJ + 8)(%rsp), %rdx", "\tshrdq\t$BARS, %rdx, %rax",
		"\tmovq\t$BAR, %rdx", "\tmulxq\t%rax, %rax, %rdx", "",
		"\t/* Subtract the low halves of q * p, keeping the high halves in t. "
			"*/"]
	for i in range(n):
		o.append("\tmovq\t$P%d, %%rax" % i)
		o.append("\tmulxq\t%rax, %rax, %rcx")
		o.append("\t%s\t%%rax, "
			"%d(%%rsp)" % ("subq" if i == 0 else "sbbq", 8 * i))
		o.append("\tmovq\t%%rcx, %d(%%rsp)" % (t + 8 * i))
	o.append("\tsbbq\t$0, %d(%%rsp)" % (8 * n))
	o += ["", "\t/* Subtract the high halves, leaving d - q * p below 3p. */"]
	for i in range(n):
		o.append("\tmovq\t%d(%%rsp), %%rax" % (t + 8 * i))
		o.append("\t%s\t%%rax, "
			"%d(%%rsp)" % ("subq" if i == 0 else "sbbq", 8 * (i + 1)))
	o += ["",
		"\t/* Subtract p twice, keeping the difference when there is no "
			"borrow. */",
		"\t.rept 2"]
	for i in range(n):
		o.append("\tmovq\t%d(%%rsp), %%rax" % (8 * i))
		o.append("\tmovq\t$P%d, %%rdx" % i)
		o.append("\t%s\t%%rdx, %%rax" % ("subq" if i == 0 else "sbbq"))
		o.append("\tmovq\t%%rax, %d(%%rsp)" % (t + 8 * i))
	o += ["\tmovq\t%d(%%rsp), %%rax" % (8 * n), "\tsbbq\t$0, %rax",
		"\tmovq\t%%rax, "
			"%d(%%rsp)" % (t + 8 * n), "\tsbbq\t%rbx, %rbx", "\tnotq\t%rbx"]
	for i in range(n + 1):
		o += ["\tmovq\t%d(%%rsp), "
			"%%rax" % (8 * i), "\tmovq\t%d(%%rsp), %%rdx" % (t + 8 * i),
			"\txorq\t%rax, %rdx", "\tandq\t%rbx, %rdx", "\txorq\t%rdx, %rax",
			"\tmovq\t%%rax, %d(%%rsp)" % (8 * i)]
	o += ["\t.endr", ""]
	for i in range(n):
		o += ["\tmovq\t%d(%%rsp), "
			"%%rax" % (8 * i), "\tmovq\t%%rax, %d(%%rdi)" % (8 * i)]
	o += ["\taddq\t$%d, %%rsp" % (16 * (n + 1)), "\tpop\t%rbx", "\tret", ""]
	regs = ", ".join(REGS[:n + 1] + ["%rax"])
	for name, rdc in (("muln", 0), ("mulm", 1)):
		o += ["cdecl(fp_%s_low):" % name] + PUSHM + ["\tsubq\t$FRAME, %rsp", "",
			"\tmovq\t%rdi, CPTR", "\tmovq\t%rsi, APTR", "\tmovq\t$0, ZEROS",
			"\tmovq\t$-1, ONES", "\tmovq\t$0, CARRY", "\t.set\tk, 0",
			"\t.rept\tRLC_FP_DIGS", "\tmovq\t8*k(%rdx), %rax",
				"\tmovq\t%rax, 8*k+BCPY",
			"\t.set\tk, k + 1", "\t.endr", "",
			"\tMULM\tAPTR, BCPY, %s" % regs,
			"\tFP_MUL_LOW\tAPTR, BCPY, %s, p0(%%rip), %d" % (regs, rdc), "",
			"\taddq\t$FRAME, %rsp"] + POPM
		if name == "muln":
			o.append("")
	return o


def rdc_low(g):
	n = g.n
	regs = ["%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15",
		"%rbx",
		"%rbp", "%rax", "%rcx"][:n]
	return ['#include '
		'"relic_fp_low.h"', "", '#include "macro.s"', "", ".text", "",
		".global cdecl(fp_rdcn_low)", "", "/*", " * Function: fp_rdcn_low",
		" * Inputs: rdi = c, rsi = "
			"a", " * Output: c = a/R mod p, for a < pR", " */",
		"cdecl(fp_rdcn_low):"] + PUSHM + ["\tsubq\t$FRAME, %rsp", "",
		"\tmovq\t%rdi, CPTR", "\tmovq\t$0, ZEROS", "\tmovq\t$-1, ONES",
		"\tFP_RDCN_LOW\t0(%%rsi), %s, %%rdi, p0(%%rip)" % ", ".join(regs), "",
		"\taddq\t$FRAME, %rsp"] + POPM


def sqr_low(g):
	n = g.n
	z = REGS[:n]
	t0 = REGS[n]
	o = ['#include "relic_fp_low.h"', '#include "macro.s"', "", ".text",
		".global cdecl(fp_sqrn_low)", ".global cdecl(fp_sqrm_low)", ""]
	for name, rdc, doc in (("sqrn", 0, "c = a^2"), ("sqrm", 1,
		"c = a^2/R mod p")):
		o += ["/*", " * Function: fp_%s_low" % name,
			" * Inputs: rdi = c, rsi = a",
			" * Output: "
				"%s" % doc, " */", "cdecl(fp_%s_low):" % name] + PUSHM + [
			"\tsubq\t$SFRAME, %rsp", "", "\tmovq\t%rdi, CPTR"]
		if rdc:
			o += ["\tmovq\t$0, ZEROS", "\tmovq\t$-1, ONES"]
		o += ["\t.set\tk, 0", "\t.rept\tRLC_FP_DIGS", "\tmovq\t8*k(%rsi), %rax",
			"\tmovq\t%rax, 8*k+BCPY", "\t.set\tk, k + 1", "\t.endr", "",
			"\tFP_SQR_LOW\tBCPY, SBUF, %s, %s, %%rax, p0(%%rip), "
				"%d" % (", ".join(z), t0, rdc),
			"", "\taddq\t$SFRAME, %rsp"] + POPM
		if name == "sqrn":
			o.append("")
	return o


def shift_low(g):
	n = g.n
	o = ['#include "relic_fp_low.h"', '#include "macro.s"', "", ".text",
		".global cdecl(fp_rsh1_low)", ".global cdecl(fp_lsh1_low)", "", "/*",
		" * The digits are shifted in place from one end, so c may alias "
			"a.", " */",
		"cdecl(fp_rsh1_low):", "\tmovq\t0(%rsi), %r8", "\tmovq\t%r8, %rax",
		"\tandq\t$1, %rax"]
	cur, nxt = "%r8", "%r9"
	for i in range(1, n):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, nxt))
		o.append("\tshrd\t$1, %s, %s" % (nxt, cur))
		o.append("\tmovq\t%s, %d(%%rdi)" % (cur, 8 * (i - 1)))
		cur, nxt = nxt, cur
	o += ["\tshrq\t$1, "
		"%s" % cur, "\tmovq\t%s, %d(%%rdi)" % (cur, 8 * (n - 1)), "\tret", "",
		"cdecl(fp_lsh1_low):", "\tmovq\t%d(%%rsi), %%r8" % (8 * (n - 1)),
			"\tmovq\t%r8, %rax",
		"\tshrq\t$63, %rax"]
	cur, nxt = "%r8", "%r9"
	for i in range(n - 2, -1, -1):
		o.append("\tmovq\t%d(%%rsi), %s" % (8 * i, nxt))
		o.append("\tshld\t$1, %s, %s" % (nxt, cur))
		o.append("\tmovq\t%s, %d(%%rdi)" % (cur, 8 * (i + 1)))
		cur, nxt = nxt, cur
	o += ["\tshlq\t$1, %s" % cur, "\tmovq\t%s, 0(%%rdi)" % cur, "\tret"]
	return o


def write_all(g, out):
	for name, fn in (("relic_fp_add_low.s", add_low), ("relic_fp_mul_low.s",
		mul_low),
			("relic_fp_rdc_low.s", rdc_low), ("relic_fp_sqr_low.s", sqr_low),
			("relic_fp_shift_low.s", shift_low)):
		text = header(name) + "\n" + "\n".join(fn(g)) + "\n"
		open(os.path.join(out, name), "w").write(text)


if __name__ == "__main__":
	main()
