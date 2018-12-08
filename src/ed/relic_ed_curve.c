/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2019 RELIC Authors
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
 * Implementation of the point addition on prime elliptic twisted Edwards curves.
 *
 * @version $Id$
 * @ingroup ed
 */

#include "relic_core.h"

void ed_curve_init(void) {
	ctx_t *ctx = core_get();
#ifdef ED_PRECO
	for (int i = 0; i < RELIC_ED_TABLE; i++) {
		ctx->ed_ptr[i] = &(ctx->ed_pre[i]);
	}
#endif
	ed_set_infty(&ctx->ed_g);
	bn_init(&ctx->ed_r, FP_DIGS);
	bn_init(&ctx->ed_h, FP_DIGS);
#if defined(ED_ENDOM) && (ED_MUL == LWNAF || ED_FIX == COMBS || ED_FIX == LWNAF || !defined(STRIP))
	for (int i = 0; i < 3; i++) {
		bn_init(&(ctx->ed_v1[i]), FP_DIGS);
		bn_init(&(ctx->ed_v2[i]), FP_DIGS);
	}
#endif
}

void ed_curve_clean(void) {
	ctx_t *ctx = core_get();
	bn_clean(&ctx->ed_r);
	bn_clean(&ctx->ed_h);
#if defined(ED_ENDOM) && (ED_MUL == LWNAF || ED_FIX == LWNAF || !defined(STRIP))
	for (int i = 0; i < 3; i++) {
		bn_clean(&(ctx->ed_v1[i]));
		bn_clean(&(ctx->ed_v2[i]));
	}
#endif
}
