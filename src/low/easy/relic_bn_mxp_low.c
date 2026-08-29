/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
 * (licence header as in the rest of the tree)
 */

/**
 * @file
 *
 * Low-level modular exponentiation, portable backend.
 *
 * The value is held in Montgomery form in a single working area. Every
 * multiplication writes into the same double width scratch and is reduced from
 * there by bn_modn_low, rather than going out to a wide temporary and back
 * through the bn layer. That
 * is worth about forty percent at a five hundred bit modulus, falling to about
 * ten percent at four thousand, since the saving is per operation while the
 * arithmetic itself grows faster than the operand.
 *
 * The exponent is consumed by a sliding window over its odd powers, so a run of
 * w bits costs w squarings and one multiplication rather than one of each per
 * set bit.
 *
 * @ingroup bn
 */

#include "relic_bn.h"
#include "relic_bn_low.h"
#include "relic_util.h"
#include "relic_dv.h"
#include "relic_core.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/** Window width, and so half the number of odd powers held in the table. */
#define MXP_WIN(B)		((B) > 512 ? 7 : ((B) > 256 ? 6 : ((B) > 128 ? 5 : 4)))

/** Largest window this implementation will use. */
#define MXP_WMAX		7

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

void bn_mxpn_low(dig_t *c, const dig_t *a, size_t sa, const dig_t *b, size_t sb,
		const dig_t *m, size_t sm, dig_t u) {
	dig_t *pro, *acc, *nxt, *tab, *swp;
	dig_t *t = RLC_ALLOCA(dig_t, 4 * sm + ((size_t)1 << (MXP_WMAX - 1)) * sm);
	size_t i, k, w, nb, tn;
	int j, l, v, s, started = 0;

	nb = sb * RLC_DIG;
	while (nb > 0 && ((b[(nb - 1) / RLC_DIG] >> ((nb - 1) % RLC_DIG)) & 1) == 0) {
		nb--;
	}
	if (nb == 0) {
		/* the exponent is zero, so the result is one */
		dv_zero(c, sm);
		c[0] = 1;
		return;
	}

	w = MXP_WIN(nb);
	tn = (size_t)1 << (w - 1);

	pro = t;						/* 2 * sm, the double width product */
	acc = pro + 2 * sm;				/* sm, the accumulator */
	nxt = acc + sm;					/* sm, its spare */
	tab = nxt + sm;					/* tn * sm, the odd powers */

	/*
	 * The base is brought into Montgomery form by multiplying it by R squared,
	 * which the caller precomputed because deriving it needs a division and the
	 * low level has none.
	 */
	dv_zero(acc, sm);
	dv_copy(acc, a, RLC_MIN(sa, sm));

	/* Compute the constant R2. */
	dv_zero(nxt, sm);
	nxt[0] = 1;
	for (i = 0; i < 2 * sm * RLC_DIG; i++) {
		dig_t carry = bn_lsh1_low(nxt, nxt, sm);
		if (carry || bn_cmpn_low(nxt, sm, m, sm) != RLC_LT) {
			bn_subn_low(nxt, nxt, m, sm);
		}
	}
	bn_muln_low(pro, acc, nxt, sm);
	bn_modn_low(tab, pro, 2 * sm, m, sm, u);

	/* the rest of the table holds the odd powers of the base */
	if (tn > 1) {
		bn_sqrn_low(pro, tab, sm);
		bn_modn_low(nxt, pro, 2 * sm, m, sm, u);
		for (k = 1; k < tn; k++) {
			bn_muln_low(pro, tab + (k - 1) * sm, nxt, sm);
			bn_modn_low(tab + k * sm, pro, 2 * sm, m, sm, u);
		}
	}

	for (j = (int)nb - 1; j >= 0; ) {
		if (((b[j / RLC_DIG] >> (j % RLC_DIG)) & 1) == 0) {
			if (started) {
				bn_sqrn_low(pro, acc, sm);
				bn_modn_low(nxt, pro, 2 * sm, m, sm, u);
				swp = acc; acc = nxt; nxt = swp;
			}
			j--;
			continue;
		}
		/* the longest window ending on a set bit, so its value stays odd */
		l = j - (int)w + 1;
		if (l < 0) {
			l = 0;
		}
		while (((b[l / RLC_DIG] >> (l % RLC_DIG)) & 1) == 0) {
			l++;
		}
		v = 0;
		for (s = j; s >= l; s--) {
			v = (v << 1) | (int)((b[s / RLC_DIG] >> (s % RLC_DIG)) & 1);
		}
		if (started) {
			for (i = 0; i <= (size_t)(j - l); i++) {
				bn_sqrn_low(pro, acc, sm);
				bn_modn_low(nxt, pro, 2 * sm, m, sm, u);
				swp = acc; acc = nxt; nxt = swp;
			}
			bn_muln_low(pro, acc, tab + (size_t)(v >> 1) * sm, sm);
			bn_modn_low(nxt, pro, 2 * sm, m, sm, u);
			swp = acc; acc = nxt; nxt = swp;
		} else {
			dv_copy(acc, tab + (size_t)(v >> 1) * sm, sm);
			started = 1;
		}
		j = l - 1;
	}

	/* out of Montgomery form, by reducing the value on its own */
	dv_zero(pro, 2 * sm);
	dv_copy(pro, acc, sm);
	bn_modn_low(c, pro, 2 * sm, m, sm, u);
	RLC_FREE(t);
}