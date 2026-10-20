#!/usr/bin/env python3
"""
Migrates C code written against the old configuration names of RELIC.

The configuration macros of relic_conf.h now carry prefixes, so that they do
not clash with other libraries:

- global options, switches and their values get RLC_, for example
  CHECK -> RLC_CHECK, ALLOC == AUTO -> RLC_ALLOC == RLC_AUTO, and
  OPSYS == LINUX -> RLC_OPSYS == RLC_LINUX;
- method values get the prefix of their module, taken from the option they are
  compared with, for example FP_RDC == MONTY -> FP_RDC == FP_MONTY;
- coordinate systems of points get EC_, for example p->coord == BASIC ->
  p->coord == EC_AFFIN.

The CMake options and their values keep their old names, so only C code needs
changes. Identifiers inside string and character literals are left alone.
Comments on preprocessor lines are renamed like code. Other comments get their
options renamed, but values only after an option and a comparison, so prose
keeps words such as GMP. Running the script twice changes nothing more.

Usage: tools/relic-rename-conf.py [-v VALUE[,VALUE...]] [FILE...]
Without files, it rewrites the C sources, headers and assembly files that git
tracks in the current directory. The -v option adds method values that the
script does not know, such as those of a branch adding a new method, so that
they get the prefix of their module too.
"""

import argparse
import re
import subprocess

# Global options and switches, then their values, which become RLC_ names.
OPTIONS = '''
	ARCH RAND SEED TIMER MULTI
	DEBUG CHECK VERBS DOCUM STRIP QUIET COLOR SHLIB STLIB ALLOC ALIGN WSIZE
	CORES BENCH TESTS OPSYS ARITH
'''.split()
GLOBAL = OPTIONS + '''
	AUTO DYNAMIC EASY GMP GMP_SEC
	LINUX FREEBSD MACOSX WINDOWS DROID DUINO NETBSD
	AVR MSP ARM A64 X86 X64
	OPENMP PTHREAD HREAL HPROC HTHRD ANSI CYCLE PERF
	HASHD UDEV CALL RDRND WCGR
'''.split()

# Method values, which take the prefix of the option they are compared with.
METHODS = '''
	BASIC COMBA MULTP BARRT MONTY PMERS SLIDE BINAR LEHME LOWER INTEG QUICK
	EXGCD DIVST JMPDS LAZYR ITOHT CTAIA LODAH PROJC JACOB EXTND LWNAF LWREG
	RWNAF COMBD HALVE SSWUM SWIFT PRIME CHAR2 EDDIE TATEP WEILP OATEP SH224
	SH256 SH384 SH512 B2S160 B2S256
'''.split()

# Coordinate systems of points.
COORD = {'BASIC': 'EC_AFFIN', 'PROJC': 'EC_PROJC', 'JACOB': 'EC_JACOB',
		'EXTND': 'EC_EXTND', 'HALVE': 'EC_HALVE'}

MODS = 'BN|FPX|FP|FBX|FB|EPX|EP|EB|ED|EC|PP|PC|MD|BC|CP|MPC'
PAIR = PAIR_CMT = None


def compile_pairs(values):
	"""Builds the patterns that pair method values with their options."""
	global PAIR, PAIR_CMT
	vals = '|'.join(sorted(values, key=len, reverse=True))
	PAIR = re.compile(r'(\b(%s)_[A-Z0-9]+\s*(?:==|!=)\s*)(%s)\b' %
			(MODS, vals))
	PAIR_CMT = re.compile(r'(\b(%s)_[A-Z0-9]+\s*(?:==|!=|=)\s*)(%s)\b' %
			(MODS, vals))
CRD = re.compile(r'(\bcoord\s*(?:==|!=|=)\s*)(%s)\b' % '|'.join(COORD))
CASE_CRD = re.compile(r'(\bcase\s+)(%s)(\s*:)' % '|'.join(COORD))
SWITCH_CRD = re.compile(r'switch\s*\([^)]*\bcoord\s*\)')
CASE_MD = re.compile(
		r'(\bcase\s+)(SH224|SH256|SH384|SH512|B2S160|B2S256)(\s*:)')
SWITCH_MD = re.compile(r'switch\s*\(\s*MD_MAP\s*\)')
WORD = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
# In comments, a value is renamed only after an option and a comparison, since
# values such as GMP or ANSI are also words.
VALUE_CMT = re.compile(r'(\bRLC_(?:%s)\s*(?:==|!=|=)\s*)(%s)\b' % (
		'|'.join(OPTIONS), '|'.join(v for v in GLOBAL if v not in OPTIONS)))


def fix_code(text):
	"""Renames identifiers in code, outside literals and comments."""
	text = WORD.sub(lambda m: 'RLC_' + m.group(0)
			if m.group(0) in GLOBAL else m.group(0), text)
	text = text.replace('RLC_ALIGN(', 'RLC_ALIGN_UP(')
	text = PAIR.sub(lambda m: m.group(1) + m.group(2) + '_' + m.group(3), text)
	text = CRD.sub(lambda m: m.group(1) + COORD[m.group(2)], text)
	text = text.replace('RLC_SEED == ZERO', 'RLC_SEED == RLC_NONE')
	return text


def fix_switches(text):
	"""Renames the cases of switches on coordinates or on the hash function,
	matching the braces of each switch."""
	for switch, case, fix in ((SWITCH_CRD, CASE_CRD, lambda m: m.group(1) +
			COORD[m.group(2)] + m.group(3)), (SWITCH_MD, CASE_MD, lambda m:
			m.group(1) + 'MD_' + m.group(2) + m.group(3))):
		pos = 0
		while True:
			m = switch.search(text, pos)
			if not m:
				break
			start = text.find('{', m.end())
			depth, end = 0, start
			while end < len(text):
				if text[end] == '{':
					depth += 1
				elif text[end] == '}':
					depth -= 1
					if depth == 0:
						break
				end += 1
			body = case.sub(fix, text[start:end])
			text = text[:start] + body + text[end:]
			pos = start + len(body)
	return text


def fix_comment(text, directive):
	"""Renames the same identifiers in a comment. A comment on a preprocessor
	line labels a condition, so all of it is renamed. Elsewhere, options are
	renamed everywhere but values only after an option and a comparison, as in
	ALLOC = DYNAMIC, since prose uses values such as GMP or ANSI as words."""
	names = GLOBAL if directive else OPTIONS
	text = WORD.sub(lambda m: 'RLC_' + m.group(0)
			if m.group(0) in names else m.group(0), text)
	if not directive:
		text = VALUE_CMT.sub(lambda m: m.group(1) + 'RLC_' + m.group(2), text)
	return PAIR_CMT.sub(lambda m: m.group(1) + m.group(2) + '_' +
			m.group(3), text)


def migrate(text):
	"""Splits a file into code, comments and literals, and renames the first
	two."""
	out, code, i, n = [], [], 0, len(text)

	def on_directive(k):
		line = text[text.rfind('\n', 0, k) + 1:k]
		return line.lstrip().startswith('#')

	def flush():
		if code:
			out.append(fix_code(''.join(code)))
			code.clear()

	while i < n:
		c = text[i]
		if text.startswith('/*', i):
			flush()
			j = text.find('*/', i + 2)
			j = n if j < 0 else j + 2
			out.append(fix_comment(text[i:j], on_directive(i)))
			i = j
		elif text.startswith('//', i):
			flush()
			j = text.find('\n', i)
			j = n if j < 0 else j
			out.append(fix_comment(text[i:j], on_directive(i)))
			i = j
		elif c in '"\'':
			flush()
			j = i + 1
			while j < n and text[j] != c and text[j] != '\n':
				j += 2 if text[j] == '\\' else 1
			j = min(j + 1, n)
			out.append(text[i:j])
			i = j
		else:
			code.append(c)
			i += 1
	flush()
	return fix_switches(''.join(out))


def main():
	parser = argparse.ArgumentParser(description='Migrates C code to the '
			'prefixed configuration names of RELIC.')
	parser.add_argument('-v', '--values', default='',
			help='extra method values, separated by commas')
	parser.add_argument('files', nargs='*', help='files to rewrite')
	args = parser.parse_args()
	extra = [v for v in args.values.split(',') if v]
	bad = [v for v in extra if not re.fullmatch(r'[A-Z][A-Z0-9]*', v)]
	if bad:
		parser.error('method values must be upper case: ' + ', '.join(bad))
	compile_pairs(METHODS + extra)
	files = args.files
	if not files:
		files = subprocess.run(['git', 'ls-files', '*.c', '*.h', '*.s', '*.S'],
				capture_output=True, text=True, check=True).stdout.split()
		files = [f for f in files if not f.endswith('include/relic_label.h')]
	changed = 0
	for f in files:
		with open(f, errors='surrogateescape') as h:
			text = h.read()
		new = migrate(text)
		if new != text:
			with open(f, 'w', errors='surrogateescape') as h:
				h.write(new)
			changed += 1
	print('Rewrote %d of %d files.' % (changed, len(files)))


if __name__ == '__main__':
	main()
