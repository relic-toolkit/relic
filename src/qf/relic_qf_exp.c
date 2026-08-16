/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2025 RELIC Authors
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
 * Implementation of the binary quadratic form exponentiation.
 *
 * @ingroup qf
 */

#include "relic_core.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

#define QF_NAF_WIDTH	7

void qf_exp(qf_t r, const qf_t f, const bn_t n, const bn_t bound) {
	qf_t ff, tab[1 << (QF_NAF_WIDTH - 2)];
	int8_t *naf = NULL;
	size_t i, u, w, bits, len;
	int j, first;

	if (bn_is_zero(n)) {
		qf_set_one(r, bound);
		return;
	}

	/* Window width: the table costs one composition per entry, so scale it
	 * with the exponent instead of always paying for QF_NAF_WIDTH. */
	bits = bn_bits(n);
	w = 3;
	if (bits > 64) w = 4;
	if (bits > 160) w = 5;
	if (bits > 480) w = 6;
	if (bits > 1024) w = 7;
	u = (size_t)1 << (w - 2);

	for (i = 0; i < u; i++) {
		qf_new(tab[i]);
	}
	qf_new(ff);

	RLC_TRY {
		len = bn_bits(n) + 1;
		naf = malloc(len);
		if (naf == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		bn_rec_naf(naf, &len, n, w);

		/* tab[i] = f^(2i+1) for 0 <= i < 2^(w-2) */
		qf_dup(ff, f, bound);
		qf_copy(tab[0], f);
		for (i = 1; i < u; i++) {
			qf_com(tab[i], tab[i - 1], ff, 0, bound);
		}

		first = 1;
		for (j = (int)len - 1; j >= 0; j--) {
			if (!first) {
				qf_dup(r, r, bound);
			}
			if (naf[j] != 0) {
				int d = naf[j];
				size_t idx = (size_t)((d > 0 ? d : -d) - 1) / 2;
				if (first) {
					qf_copy(r, tab[idx]);
					if (d < 0) {
						qf_neg(r, r);
					}
					first = 0;
				} else {
					qf_com(r, r, tab[idx], d < 0, bound);
				}
			}
		}
		if (first) {
			qf_set_one(r, bound);
		}
		if (bn_sign(n) == RLC_NEG) {
			qf_neg(r, r);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		free(naf);
		qf_free(ff);
		for (i = 0; i < u; i++) {
			qf_free(tab[i]);
		}
	}
}

void qf_exp_sim(qf_t r, const qf_t f0, const bn_t n0, const qf_t f1,
		const bn_t n1, const bn_t bound) {
	qf_t tab[5];
	int8_t *jsf = NULL;
	size_t i, len, offset;
	int j;

	if (bn_is_zero(n0)) {
		qf_exp(r, f1, n1, bound);
		return;
	}
	if (bn_is_zero(n1)) {
		qf_exp(r, f0, n0, bound);
		return;
	}

	for (i = 0; i < 5; i++) {
		qf_new(tab[i]);
	}

	RLC_TRY {
		/* Same table layout as RELIC's ep_mul_sim_joint. */
		qf_set_one(tab[0], bound);
		qf_copy(tab[1], f1);
		qf_copy(tab[2], f0);
		qf_com(tab[3], f0, f1, 0, bound);
		qf_com(tab[4], f0, f1, 1, bound);

		offset = RLC_MAX(bn_bits(n0), bn_bits(n1)) + 1;
		len = 2 * offset;
		jsf = malloc(len);
		if (jsf == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		bn_rec_jsf(jsf, &len, n0, n1);

		qf_set_one(r, bound);
		for (j = (int)len - 1; j >= 0; j--) {
			int d;
			qf_dup(r, r, bound);
			d = jsf[j] * 2 + jsf[j + offset];
			if (jsf[j] != 0 && jsf[j] == -jsf[j + offset]) {
				qf_com(r, r, tab[4], d < 0, bound);
			} else if (d != 0) {
				qf_com(r, r, tab[d > 0 ? d : -d], d < 0, bound);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		free(jsf);
		for (i = 0; i < 5; i++) {
			qf_free(tab[i]);
		}
	}
}

/*
 * Fixed-base exponentiation.  n is split as
 *   n = n0 + n1*2^e + n2*2^d + n3*2^(d+e),
 * with d and e chosen at setup so that every chunk is at most e bits, and the
 * four bases f, f^(2^e), f^(2^d), f^(2^(d+e)) are consumed by a single e-bit
 * simultaneous exponentiation with a 15-entry table.  BICYCL splits the same
 * way but pairs a width-2 comb with Solinas' JSF instead.
 */
void qf_exp_fix(qf_t r, const qf_t f, const bn_t n, size_t d, size_t e,
		const qf_t fe, const qf_t fd, const qf_t fde, const bn_t bound) {
	qf_t tab[16];
	bn_t chunk[4];
	size_t i, bits, max;

	if (bn_is_zero(n)) {
		qf_set_one(r, bound);
		return;
	}
	if (bn_bits(n) < e) {
		qf_exp(r, f, n, bound);
		return;
	}

	for (i = 0; i < 16; i++) {
		qf_new(tab[i]);
	}
	for (i = 0; i < 4; i++) {
		bn_null(chunk[i]);
	}

	RLC_TRY {
		for (i = 0; i < 4; i++) {
			bn_new(chunk[i]);
		}
		/* chunks: bits [0, e), [e, d), [d, d+e), [d+e, .) */
		bn_mod_2b(chunk[0], n, e);
		bn_rsh(chunk[1], n, e);
		bn_mod_2b(chunk[1], chunk[1], d - e);
		bn_rsh(chunk[2], n, d);
		bn_mod_2b(chunk[2], chunk[2], e);
		bn_rsh(chunk[3], n, d + e);

		/* tab[i] = product of the bases selected by the bits of i */
		qf_set_one(tab[0], bound);
		qf_copy(tab[1], f);
		qf_copy(tab[2], fe);
		qf_copy(tab[4], fd);
		qf_copy(tab[8], fde);
		for (i = 3; i < 16; i++) {
			if (i == 4 || i == 8) {
				continue;
			}
			/* strip the lowest set bit and compose */
			{
				size_t low = i & (~i + 1);
				qf_com(tab[i], tab[i - low], tab[low], 0, bound);
			}
		}

		max = 0;
		for (i = 0; i < 4; i++) {
			bits = bn_bits(chunk[i]);
			max = RLC_MAX(max, bits);
		}

		qf_set_one(r, bound);
		for (i = max; i > 0; i--) {
			size_t idx = 0, j;
			qf_dup(r, r, bound);
			for (j = 0; j < 4; j++) {
				idx |= (size_t)bn_get_bit(chunk[j], i - 1) << j;
			}
			if (idx != 0) {
				qf_com(r, r, tab[idx], 0, bound);
			}
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		for (i = 0; i < 4; i++) {
			bn_free(chunk[i]);
		}
		for (i = 0; i < 16; i++) {
			qf_free(tab[i]);
		}
	}
}
