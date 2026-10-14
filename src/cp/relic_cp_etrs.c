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
 * Implementation of extendable threshold ring signatures, from
 * "Count Me In! Extendability for Threshold Ring Signatures" by Aranha,
 * Hall-Andersen, Nitulescu, Pagnin and Yakoubov (PKC 2022):
 * https://eprint.iacr.org/2021/1240.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/**
 * Evaluates in the exponent at x the polynomial through the k points
 * (xs[i], ys[i]), from the Lagrange coefficients at x. When the discrete
 * logarithms td of ys[1], ..., ys[k - 1] are known, the result is computed
 * with two scalar multiplications instead of a multiple one.
 *
 * @param[out] r			- the result.
 * @param[in] x				- the evaluation point.
 * @param[in] xs			- the abscissas of the points.
 * @param[in] ys			- the ordinates of the points.
 * @param[in] td			- the discrete logarithms of ys[1, ...], or NULL.
 * @param[in] w				- the barycentric weights of the abscissas.
 * @param[in] k				- the number of points.
 * @param[in] n				- the order of the group.
 * @param[in, out] v		- a temporary array with room for k integers.
 */
static void etrs_evl(ec_t r, const bn_t x, const bn_t *xs, const ec_t *ys,
		const bn_t *td, const bn_t *w, size_t k, const bn_t n, bn_t *v) {
	bn_t l, u;

	bn_null_all(l, u);

	RLC_TRY {
		bn_new_all(l, u);

		bn_lag_fix(v, x, xs, w, n, k);
		if (td != NULL) {
			bn_zero(l);
			for (size_t i = 1; i < k; i++) {
				bn_mul(u, v[i], td[i - 1]);
				bn_add(l, l, u);
				bn_mod(l, l, n);
			}
			ec_mul_sim_gen(r, l, ys[0], v[0]);
		} else {
			ec_mul_sim_lot(r, ys, (const bn_t *)v, k);
		}
	}
	RLC_CATCH_ANY {
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(l, u);
	}
}

/**
 * Collects the points of the polynomial: (0, pp) unless pp is NULL, the unused
 * trapdoors and the members of the ring, in this order.
 *
 * @param[out] xs			- the abscissas of the points.
 * @param[out] ys			- the ordinates of the points.
 * @param[in] td			- the trapdoors, zero when already used.
 * @param[in] y				- the abscissas of the trapdoors.
 * @param[in] max			- the number of trapdoors.
 * @param[in] p				- the ring of signatures.
 * @param[in] size			- the number of signatures in the ring.
 * @param[in] pp			- the public parameters, or NULL.
 * @param[in] n				- the order of the group.
 * @return the number of points.
 */
static size_t etrs_pts(bn_t *xs, ec_t *ys, const bn_t *td, const bn_t *y,
		size_t max, const etrs_t *p, size_t size, const ec_t pp, const bn_t n) {
	size_t k = 0;

	if (pp != NULL) {
		bn_zero(xs[k]);
		ec_copy(ys[k++], pp);
	}
	for (size_t i = 0; i < max; i++) {
		if (!bn_is_zero(td[i])) {
			bn_mod(xs[k], y[i], n);
			ec_mul_gen(ys[k++], td[i]);
		}
	}
	for (size_t i = 0; i < size; i++) {
		bn_mod(xs[k], p[i]->y, n);
		ec_copy(ys[k++], p[i]->h);
	}
	return k;
}

/**
 * Computes the digest of the commitment to the polynomial, the evaluations
 * V_1, ..., V_deg of the polynomial in the exponent.
 *
 * @param[out] d			- the digest of the commitment.
 * @param[in] com			- the commitment.
 * @param[in] deg			- the degree of the polynomial.
 */
static void etrs_dig(uint8_t *d, const ec_t *com, size_t deg) {
	const size_t size = deg * (RLC_FC_BYTES + 1);
	uint8_t *buf = RLC_ALLOCA(uint8_t, size + 1);

	if (buf == NULL) {
		RLC_THROW(ERR_NO_MEMORY);
		return;
	}

	memset(buf, 0, size);
	for (size_t i = 0; i < deg; i++) {
		ec_write_bin(buf + i * (RLC_FC_BYTES + 1), ec_size_bin(com[i], 1),
				com[i], 1);
	}
	md_map(d, buf, size);
	RLC_FREE(buf);
}

/**
 * Adds a member to a signature, which takes the degree and the commitment of
 * the signature. With a private key, the member signs at a new point of the
 * polynomial. Without one, the member spends an unused trapdoor, which is the
 * discrete logarithm of the point at its abscissa.
 *
 * @param[in, out] td		- the trapdoors, zeroed when used.
 * @param[in, out] y		- the abscissas of the trapdoors, zeroed when used.
 * @param[in] max			- the number of trapdoors.
 * @param[in, out] p		- the ring of signatures.
 * @param[in, out] size		- the number of signatures in the ring.
 * @param[in] com			- the commitment to the polynomial.
 * @param[in] msg			- the message.
 * @param[in] len			- the message length.
 * @param[in] sk			- the private key of the new member, or NULL.
 * @param[in] pk			- the public key of the new member.
 * @return RLC_OK if no errors occurred, RLC_ERR otherwise.
 */
static int etrs_join(bn_t *td, bn_t *y, size_t max, etrs_t *p, size_t *size,
		const ec_t *com, const uint8_t *msg, size_t len, const bn_t sk,
		const ec_t pk) {
	/* Only a new point of the polynomial needs the points it goes through. */
	const size_t k = (sk == NULL ? 0 : max + *size);
	size_t i = max, deg;
	bn_t n, *b = NULL;
	ec_t w[2], *ys = NULL;
	uint8_t *buf;
	int result = RLC_OK;

	/* The new member joins a signature, taking its degree. */
	if (*size == 0) {
		return RLC_ERR;
	}
	for (size_t j = 0; j < *size; j++) {
		if (ec_cmp(pk, p[j]->pk) == RLC_EQ) {
			return RLC_ERR;
		}
	}
	if (sk == NULL) {
		/* Pick an unused trapdoor, if any is left. */
		for (i = 0; i < max && bn_is_zero(td[i]); i++);
		if (i == max) {
			return RLC_ERR;
		}
	}

	deg = p[0]->deg;
	if (k > 0) {
		b = RLC_ALLOCA(bn_t, 3 * k);
		ys = RLC_ALLOCA(ec_t, k);
	}
	buf = RLC_ALLOCA(uint8_t, len + RLC_MD_LEN);
	if ((k > 0 && (b == NULL || ys == NULL)) || buf == NULL) {
		RLC_FREE(b);
		RLC_FREE(ys);
		RLC_FREE(buf);
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null(n);
	ec_null_all(w[0], w[1]);
	for (size_t j = 0; j < 3 * k; j++) {
		bn_null(b[j]);
	}
	for (size_t j = 0; j < k; j++) {
		ec_null(ys[j]);
	}

	RLC_TRY {
		bn_new(n);
		ec_new_all(w[0], w[1]);
		for (size_t j = 0; j < 3 * k; j++) {
			bn_new(b[j]);
		}
		for (size_t j = 0; j < k; j++) {
			ec_new(ys[j]);
		}

		ec_curve_get_ord(n);
		if (sk != NULL &&
				etrs_pts(b, ys, td, y, max, p, *size, NULL, n) < deg + 1) {
			RLC_THROW(ERR_NO_VALID);
		} else {
			p[*size]->deg = deg;
			if (sk == NULL) {
				/* The trapdoor is the logarithm of the point at y[i]. */
				bn_copy(p[*size]->y, y[i]);
				ec_mul_gen(p[*size]->h, td[i]);
			} else {
				/* Evaluate the polynomial at a new point for the signer. */
				bn_rand_mod(p[*size]->y, n);
				bn_lag_pre(b + k, b, n, deg + 1);
				etrs_evl(p[*size]->h, p[*size]->y, b, ys, NULL, b + k,
						deg + 1, n, b + 2 * k);
				ec_norm(p[*size]->h, p[*size]->h);
			}
			ec_copy(p[*size]->pk, pk);

			/* Prove knowledge of either logarithm, signing the commitment. */
			memcpy(buf, msg, len);
			etrs_dig(buf + len, com, deg);
			ec_copy(w[0], p[*size]->h);
			ec_copy(w[1], p[*size]->pk);
			if (cp_sokor_sig(p[*size]->c, p[*size]->r, buf, len + RLC_MD_LEN,
					w, NULL, (sk == NULL ? td[i] : sk), sk == NULL) != RLC_OK) {
				RLC_THROW(ERR_CAUGHT);
			} else {
				if (sk == NULL) {
					bn_zero(td[i]);
					bn_zero(y[i]);
				}
				(*size)++;
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(n);
		ec_free_all(w[0], w[1]);
		for (size_t j = 0; j < 3 * k; j++) {
			bn_free(b[j]);
		}
		for (size_t j = 0; j < k; j++) {
			ec_free(ys[j]);
		}
		RLC_FREE(b);
		RLC_FREE(ys);
		RLC_FREE(buf);
	}
	return result;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

int cp_etrs_sig(bn_t *td, bn_t *y, size_t max, etrs_t p, ec_t *com,
		const uint8_t *msg, size_t len, const bn_t sk, const ec_t pk,
		const ec_t pp) {
	const size_t k = max + 1;
	bn_t n, x, *b = RLC_ALLOCA(bn_t, 3 * k);
	ec_t w[2], *ys = RLC_ALLOCA(ec_t, k);
	uint8_t *buf = RLC_ALLOCA(uint8_t, len + RLC_MD_LEN);
	int result = RLC_OK;

	if (b == NULL || ys == NULL || buf == NULL) {
		RLC_FREE(b);
		RLC_FREE(ys);
		RLC_FREE(buf);
		RLC_THROW(ERR_NO_MEMORY);
		return RLC_ERR;
	}

	bn_null_all(n, x);
	ec_null_all(w[0], w[1]);
	for (size_t i = 0; i < 3 * k; i++) {
		bn_null(b[i]);
	}
	for (size_t i = 0; i < k; i++) {
		ec_null(ys[i]);
	}

	RLC_TRY {
		bn_new_all(n, x);
		ec_new_all(w[0], w[1]);
		for (size_t i = 0; i < 3 * k; i++) {
			bn_new(b[i]);
		}
		for (size_t i = 0; i < k; i++) {
			ec_new(ys[i]);
		}

		/* Sample the trapdoors, which define a polynomial of degree max
		 * through (0, pp), and a new evaluation point for the signer. */
		ec_curve_get_ord(n);
		for (size_t i = 0; i < max; i++) {
			bn_rand_mod(y[i], n);
			do {
				bn_rand_mod(td[i], n);
			} while (bn_is_zero(td[i]));
		}
		etrs_pts(b, ys, td, y, max, NULL, 0, pp, n);
		bn_lag_pre(b + k, b, n, k);
		bn_rand_mod(p->y, n);
		p->deg = max;
		etrs_evl(p->h, p->y, b, ys, td, b + k, k, n, b + 2 * k);
		ec_norm(p->h, p->h);
		ec_copy(p->pk, pk);

		/* Commit to the polynomial by its evaluations at 1, ..., max, as
		 * PolySign does in the paper. These do not depend on which of the
		 * points of the polynomial are known. */
		for (size_t i = 1; i <= max; i++) {
			bn_set_dig(x, i);
			etrs_evl(com[i - 1], x, b, ys, td, b + k, k, n, b + 2 * k);
			ec_norm(com[i - 1], com[i - 1]);
		}

		/* Prove knowledge of sk, signing the commitment to the polynomial. */
		memcpy(buf, msg, len);
		etrs_dig(buf + len, (const ec_t *)com, max);
		ec_copy(w[0], p->h);
		ec_copy(w[1], p->pk);
		if (cp_sokor_sig(p->c, p->r, buf, len + RLC_MD_LEN, w, NULL, sk,
				0) != RLC_OK) {
			RLC_THROW(ERR_CAUGHT);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free_all(n, x);
		ec_free_all(w[0], w[1]);
		for (size_t i = 0; i < 3 * k; i++) {
			bn_free(b[i]);
		}
		for (size_t i = 0; i < k; i++) {
			ec_free(ys[i]);
		}
		RLC_FREE(b);
		RLC_FREE(ys);
		RLC_FREE(buf);
	}
	return result;
}

int cp_etrs_ver(size_t thres, const bn_t *td, const bn_t *y, size_t max,
		const etrs_t *s, size_t size, const ec_t *com, const uint8_t *msg,
		size_t len, const ec_t pp) {
	const size_t k = max + size;
	size_t deg, d, m;
	bn_t n, u, *b, *xs, *sc, *bx, *w, *v;
	ec_t t, h[2], *ys;
	uint8_t *buf;
	int flag = 1, result = 0;

	/* The threshold must be achievable by the ring. */
	if (thres == 0 || thres > size) {
		return 0;
	}

	deg = s[0]->deg;
	d = deg + 1;
	b = RLC_ALLOCA(bn_t, 2 * k + 4 * d);
	ys = RLC_ALLOCA(ec_t, k + d);
	buf = RLC_ALLOCA(uint8_t, len + RLC_MD_LEN);
	if (b == NULL || ys == NULL || buf == NULL) {
		RLC_FREE(b);
		RLC_FREE(ys);
		RLC_FREE(buf);
		RLC_THROW(ERR_NO_MEMORY);
		return 0;
	}
	/* Abscissas, scalars of the final check, base abscissas, weights. */
	xs = b;
	sc = b + k;
	bx = sc + k + d;
	w = bx + d;
	v = w + d;

	bn_null_all(n, u);
	ec_null_all(t, h[0], h[1]);
	for (size_t i = 0; i < 2 * k + 4 * d; i++) {
		bn_null(b[i]);
	}
	for (size_t i = 0; i < k + d; i++) {
		ec_null(ys[i]);
	}

	RLC_TRY {
		bn_new_all(n, u);
		ec_new_all(t, h[0], h[1]);
		for (size_t i = 0; i < 2 * k + 4 * d; i++) {
			bn_new(b[i]);
		}
		for (size_t i = 0; i < k + d; i++) {
			ec_new(ys[i]);
		}

		ec_curve_get_ord(n);
		for (size_t i = 0; i < size; i++) {
			flag &= (s[i]->deg == deg) && ec_on_curve(s[i]->h);
		}
		for (size_t i = 0; i < deg; i++) {
			flag &= ec_on_curve(com[i]);
		}
		/* Accept if the trapdoors and members are thres more than deg. */
		m = etrs_pts(xs, ys, td, y, max, s, size, NULL, n);
		flag &= (m >= thres + deg);
		/* The abscissas must be distinct, and distinct from that of pp. */
		for (size_t i = 0; i < m; i++) {
			flag &= !bn_is_zero(xs[i]);
			for (size_t j = 0; j < i; j++) {
				flag &= (bn_cmp(xs[i], xs[j]) != RLC_EQ);
			}
		}

		if (flag) {
			/* All points must lie on the polynomial through (0, pp) and the
			 * commitment (i, V_i). Check a random linear combination of these
			 * conditions: sum_j r_j Y_j = sum_i (sum_j r_j L_i(x_j)) B_i. */
			for (size_t i = 0; i < d; i++) {
				bn_set_dig(bx[i], i);
				bn_zero(sc[m + i]);
			}
			bn_lag_pre(w, bx, n, d);
			for (size_t j = 0; j < m; j++) {
				bn_rand_mod(sc[j], n);
				bn_lag_fix(v, xs[j], bx, (const bn_t *)w, n, d);
				for (size_t i = 0; i < d; i++) {
					/* Reduce only at the end, as the sums stay small. */
					bn_mul(u, sc[j], v[i]);
					bn_add(sc[m + i], sc[m + i], u);
				}
			}
			ec_copy(ys[m], pp);
			for (size_t i = 0; i < d; i++) {
				bn_mod(sc[m + i], sc[m + i], n);
				if (!bn_is_zero(sc[m + i])) {
					bn_sub(sc[m + i], n, sc[m + i]);
				}
				if (i > 0) {
					ec_copy(ys[m + i], com[i - 1]);
				}
			}
			ec_mul_sim_lot(t, (const ec_t *)ys, (const bn_t *)sc, m + d);
			flag &= ec_is_infty(t);

			memcpy(buf, msg, len);
			etrs_dig(buf + len, com, deg);
			for (size_t i = 0; i < size; i++) {
				ec_copy(h[0], s[i]->h);
				ec_copy(h[1], s[i]->pk);
				flag &= cp_sokor_ver(s[i]->c, s[i]->r, buf, len + RLC_MD_LEN,
						h, NULL);
			}
		}
		result = flag;
	}
	RLC_CATCH_ANY {
		result = 0;
		RLC_THROW(ERR_CAUGHT);
	}
	RLC_FINALLY {
		bn_free_all(n, u);
		ec_free_all(t, h[0], h[1]);
		for (size_t i = 0; i < 2 * k + 4 * d; i++) {
			bn_free(b[i]);
		}
		for (size_t i = 0; i < k + d; i++) {
			ec_free(ys[i]);
		}
		RLC_FREE(b);
		RLC_FREE(ys);
		RLC_FREE(buf);
	}
	return result;
}

int cp_etrs_ext(bn_t *td, bn_t *y, size_t max, etrs_t *p, size_t *size,
		const ec_t *com, const uint8_t *msg, size_t len, const ec_t pk) {
	return etrs_join(td, y, max, p, size, com, msg, len, NULL, pk);
}

int cp_etrs_uni(bn_t *td, bn_t *y, int max, etrs_t *p, size_t *size,
		const ec_t *com, const uint8_t *msg, size_t len, const bn_t sk,
		const ec_t pk) {
	return etrs_join(td, y, (max > 0 ? max : 0), p, size, com, msg, len, sk,
			pk);
}
