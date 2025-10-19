/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2009 RELIC Authors
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
 * Implementation of the multiple precision utilities.
 *
 * @ingroup bn
 */

#include <inttypes.h>

#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Statistical distance 1/2^\lambda between sampling and uniform distribution.
 */
#define RAND_DIST		40

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_copy(bn_t c, const bn_t a) {
	if (c->dp == a->dp) {
		return;
	}

	bn_grow(c, a->used);
	dv_copy(c->dp, a->dp, a->used);

	c->used = a->used;
	c->sign = a->sign;
	bn_trim(c);
}

void bn_abs(bn_t c, const bn_t a) {
	if (c->dp != a->dp) {
		bn_copy(c, a);
	}
	c->sign = RLC_POS;
}

void bn_neg(bn_t c, const bn_t a) {
	if (c->dp != a->dp) {
		bn_copy(c, a);
	}
	if (!bn_is_zero(c)) {
		c->sign = a->sign ^ 1;
	}
}

int bn_sign(const bn_t a) {
	return a->sign;
}

void bn_zero(bn_t a) {
	a->sign = RLC_POS;
	a->used = 1;
	dv_zero(a->dp, a->alloc);
}

int bn_is_zero(const bn_t a) {
	if (a->used == 0) {
		return 1;
	}
	if ((a->used == 1) && (a->dp[0] == 0)) {
		return 1;
	}
	return 0;
}

int bn_is_even(const bn_t a) {
	if (bn_is_zero(a)) {
		return 1;
	}
	if ((a->dp[0] & 0x01) == 0) {
		return 1;
	}
	return 0;
}

size_t bn_bits(const bn_t a) {
	uint_t bits;

	if (bn_is_zero(a)) {
		return 0;
	}

	/* Bits in lower digits. */
	bits = (a->used - 1) * RLC_DIG;

	return bits + util_bits_dig(a->dp[a->used - 1]);
}

int bn_get_bit(const bn_t a, uint_t bit) {
	int d;

	if (bit > bn_bits(a)) {
		return 0;
	}

	RLC_RIP(bit, d, bit);

	if (d >= a->used) {
		return 0;
	} else {
		return (a->dp[d] >> bit) & (dig_t)1;
	}
}

void bn_set_bit(bn_t a, uint_t bit, int value) {
	int d;

	RLC_RIP(bit, d, bit);

	bn_grow(a, d);

	if (value == 1) {
		a->dp[d] |= ((dig_t)1 << bit);
		if ((d + 1) > a->used) {
			a->used = d + 1;
		}
	} else {
		a->dp[d] &= ~((dig_t)1 << bit);
		bn_trim(a);
	}
}

uint_t bn_ham(const bn_t a) {
	int c = 0;

	for (int i = 0; i < bn_bits(a); i++) {
		c += bn_get_bit(a, i);
	}

	return c;
}

void bn_get_dig(dig_t *c, const bn_t a) {
	*c = a->dp[0];
}

void bn_set_dig(bn_t a, dig_t digit) {
	bn_zero(a);
	a->dp[0] = digit;
	a->used = 1;
	a->sign = RLC_POS;
}

void bn_set_2b(bn_t a, size_t b) {
	int i, d;

	if (b >= RLC_BN_SIZE * RLC_DIG) {
		RLC_THROW(ERR_NO_VALID);
	} else {
		RLC_RIP(b, d, b);

		bn_grow(a, d + 1);
		for (i = 0; i < d; i++) {
			a->dp[i] = 0;
		}
		a->used = d + 1;
		a->dp[d] = ((dig_t)1 << b);
		a->sign = RLC_POS;
	}
}

void bn_rand(bn_t a, int sign, size_t bits) {
	int digits;

	RLC_RIP(bits, digits, bits);
	digits += (bits > 0 ? 1 : 0);

	bn_grow(a, digits);

	rand_bytes((uint8_t *)a->dp, digits * sizeof(dig_t));

	a->used = digits;
	a->sign = sign;
	if (bits > 0) {
		dig_t mask = ((dig_t)1 << (dig_t)bits) - 1;
		a->dp[a->used - 1] &= mask;
	}
	bn_trim(a);
}

void bn_rand_mod(bn_t a, const bn_t b) {
	bn_t t;

	bn_null(t);

	RLC_TRY {
		bn_new(t);

		bn_copy(t, b);
		do {
			bn_rand(a, bn_sign(t), bn_bits(t) + RAND_DIST);
			bn_mod(a, a, t);
		} while (bn_is_zero(a) || bn_cmp_abs(a, t) != RLC_LT);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
	}
}

void bn_rand_frb(bn_t a, const bn_t x, const bn_t order, size_t bits) {
	size_t i, dim = RLC_CEIL(bn_bits(order), bn_bits(x));
	bn_t t, u;

	bn_null(t);
	bn_null(u);

	RLC_TRY {
		bn_new(t);
		bn_new(u);

		bits = RLC_CEIL(bits, dim);

		bn_abs(u, x);
		bn_zero(a);
		for (i = 0; i < dim; i++) {
			bn_rand(t, RLC_POS, bits);
			bn_mul(a, a, u);
			bn_add(a, a, t);
		}
		bn_mod(a, a, order);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
		bn_free(u);
	}
}

void bn_print(const bn_t a) {
	int i;

	if (a->sign == RLC_NEG) {
		util_print("-");
	}
	if (a->used == 0) {
		util_print("0\n");
	} else {
#if WSIZE == 64
		util_print_dig(a->dp[a->used - 1], 0);
		for (i = a->used - 2; i >= 0; i--) {
			util_print_dig(a->dp[i], 1);
		}
#else
		util_print_dig(a->dp[a->used - 1], 0);
		for (i = a->used - 2; i >= 0; i--) {
			util_print_dig(a->dp[i], 1);
		}
#endif
		util_print("\n");
	}
}

size_t bn_size_str(const bn_t a, uint_t radix) {
	size_t digits = 0;
	bn_t t;

	bn_null(t);

	/* Check the radix. */
	if (radix < 2 || radix > 64) {
		RLC_THROW(ERR_NO_VALID);
		return 0;
	}

	if (bn_is_zero(a)) {
		return 2;
	}

	/* Binary case requires the bits, a sign and the null terminator. */
	if (radix == 2) {
		return bn_bits(a) + (a->sign == RLC_NEG ? 1 : 0) + 1;
	}

	if (a->sign == RLC_NEG) {
		digits++;
	}

	RLC_TRY {
		bn_new(t);
		bn_copy(t, a);

		t->sign = RLC_POS;

		while (!bn_is_zero(t)) {
			bn_div_dig(t, t, (dig_t)radix);
			digits++;
		}
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	} RLC_FINALLY {
		bn_free(t);
	}

	return digits + 1;
}

void bn_read_str(bn_t a, const char *str, size_t len, uint_t radix) {
	int sign, i, j;
	char c;

	bn_zero(a);

	if (radix < 2 || radix > 64) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	j = 0;
	if (str[0] == '-') {
		j++;
		sign = RLC_NEG;
	} else {
		sign = RLC_POS;
	}

	RLC_TRY {
		bn_grow(a, RLC_CEIL(len * util_bits_dig(radix), RLC_DIG));

		while (j < len) {
			if (str[j] == 0) {
				break;
			}
			c = (char)((radix < 36) ? RLC_UPP(str[j]) : str[j]);
			for (i = 0; i < 64; i++) {
				if (c == util_conv_char(i)) {
					break;
				}
			}

			if (i < radix) {
				bn_mul_dig(a, a, (dig_t)radix);
				bn_add_dig(a, a, (dig_t)i);
			} else {
				break;
			}
			j++;
		}

		a->sign = sign;
		bn_trim(a);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
}

void bn_write_str(char *str, size_t len, const bn_t a, uint_t radix) {
	bn_t t;
	dig_t d;
	int l, i, j;
	char c;

	bn_null(t);

	l = bn_size_str(a, radix);
	if (len < l) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	if (radix < 2 || radix > 64) {
		RLC_THROW(ERR_NO_VALID);
		return;
	}

	if (bn_is_zero(a) == 1) {
		*str++ = '0';
		*str = '\0';
		return;
	}

	RLC_TRY {
		bn_new(t);
		bn_copy(t, a);

		j = 0;
		if (t->sign == RLC_NEG) {
			str[j] = '-';
			j++;
			t->sign = RLC_POS;
		}

		while (!bn_is_zero(t) && j < len) {
			bn_div_rem_dig(t, &d, t, (dig_t)radix);
			str[j++] = util_conv_char(d);
		}

		/* Reverse the digits of the string. */
		i = 0;
		if (str[0] == '-') {
			i = 1;
		}

		j = l - 2;
		while (i < j) {
			c = str[i];
			str[i] = str[j];
			str[j] = c;
			++i;
			--j;
		}

		str[l - 1] = '\0';
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free(t);
	}
}

size_t bn_size_bin(const bn_t a) {
	dig_t d;
	int digits;

	digits = (a->used - 1) * (RLC_DIG / 8);
	d = a->dp[a->used - 1];

	while (d != 0) {
		d = d >> 8;
		digits++;
	}
	return digits;
}

void bn_read_bin(bn_t a, const uint8_t *bin, size_t len) {
	int i, j;
	dig_t d = (RLC_DIG / 8);
	int digs = (len % d == 0 ? len / d : len / d + 1);

	bn_grow(a, digs);
	bn_zero(a);
	a->used = digs;

	for (i = 0; i < digs - 1; i++) {
		d = 0;
		for (j = (RLC_DIG / 8) - 1; j >= 0; j--) {
			d = d << 8;
			d |= bin[len - 1 - (i * (RLC_DIG / 8) + j)];
		}
		a->dp[i] = d;
	}
	d = 0;
	for (j = (RLC_DIG / 8) - 1; j >= 0; j--) {
		if ((int)(i * (RLC_DIG / 8) + j) < len) {
			d = d << 8;
			d |= bin[len - 1 - (i * (RLC_DIG / 8) + j)];
		}
	}
	a->dp[i] = d;

	a->sign = RLC_POS;
	bn_trim(a);
}

void bn_write_bin(uint8_t *bin, size_t len, const bn_t a) {
	size_t size, k;
	dig_t d;

	size = bn_size_bin(a);

	if (len < size) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	k = 0;
	for (int i = 0; i < a->used - 1; i++) {
		d = a->dp[i];
		for (int j = 0; j < (int)(RLC_DIG / 8); j++) {
			bin[len - 1 - k++] = d & 0xFF;
			d = d >> 8;
		}
	}

	d = a->dp[a->used - 1];
	while (d != 0) {
		bin[len - 1 - k++] = d & 0xFF;
		d = d >> 8;
	}

	while (k < len) {
		bin[len - 1 - k++] = 0;
	}
}

size_t bn_size_raw(const bn_t a) {
	return a->used;
}

void bn_read_raw(bn_t a, const dig_t *raw, size_t len) {
	RLC_TRY {
		bn_grow(a, len);
		a->used = len;
		a->sign = RLC_POS;
		dv_copy(a->dp, raw, len);
		bn_trim(a);
	} RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
}

void bn_write_raw(dig_t *raw, size_t len, const bn_t a) {
	int i, size;

	size = a->used;

	if (len < size) {
		RLC_THROW(ERR_NO_BUFFER);
		return;
	}

	for (i = 0; i < size; i++) {
		raw[i] = a->dp[i];
	}
	for (; i < len; i++) {
		raw[i] = 0;
	}
}
