#include <stdio.h>
#include <assert.h>

#include "relic.h"
#include "relic_test.h"

#define M	5			/* Number of server messages (larger). */
#define N	2			/* Number of client messages. */

static int test(void) {
	int len, result, code = RLC_ERR;
	bn_t g, n, q, r, p[M], x[M], v[N], w[N], y[N], z[M];
	g1_t u[M], ss;
	g2_t d[M + 1], s[M + 1];
	gt_t t[M];
	crt_t crt;

	bn_null(n);
	bn_null(q);
	g1_null(ss);
	crt_null(crt);

	RLC_TRY {
		bn_new(n);
		bn_new(q);
		g1_new(ss);
		for (int i = 0; i < M; i++) {
			bn_null(p[i]);
			bn_null(x[i]);
			bn_null(z[i]);
			g2_null(d[i]);
			g2_null(s[i]);
			bn_new(p[i]);
			bn_new(x[i]);
			bn_new(z[i]);
			g2_new(d[i]);
			g2_new(s[i]);
		}
		g2_null(d[M]);
		g2_new(d[M]);
		g2_null(s[M]);
		g2_new(s[M]);
		for (int i = 0; i < N; i++) {
			bn_null(v[i]);
			bn_null(w[i]);
			bn_null(y[i]);
			g1_null(u[i]);
			gt_null(t[i]);
			bn_new(v[i]);
			bn_new(w[i]);
			bn_new(y[i]);
			g1_new(u[i]);
			gt_new(t[i]);
		}

		TEST_CASE("pairing-based laconic private set intersection is correct") {
			pc_get_ord(q);
			for (int j = 0; j < M; j++) {
				bn_rand_mod(x[j], q);
			}
			for (int j = 0; j < N; j++) {
				bn_rand_mod(y[j], q);
			}
			TEST_ASSERT(cp_pbpsi_gen(q, ss, s, M) == RLC_OK, end);
			TEST_ASSERT(cp_pbpsi_ask(d, r, x, s, M) == RLC_OK, end);
			for (int k = 0; k <= N; k++) {
				for (int j = 0; j < k; j++) {
					bn_copy(y[j], x[j]);
				}
				TEST_ASSERT(cp_pbpsi_ans(t, u, ss, d[0], y, N) == RLC_OK, end);
				TEST_ASSERT(cp_pbpsi_int(z, &len, q, d, x, M, t, u, N) == RLC_OK, end);
				TEST_ASSERT(len == k, end);
			}
		} TEST_END;
	}
	RLC_CATCH_ANY {
		RLC_ERROR(end);
	}
	code = RLC_OK;
  end:
	bn_free(n);
    bn_free(q);
	g1_free(ss);
	g2_free(d);
	for (int i = 0; i < M; i++) {
		bn_free(p[i]);
		bn_free(x[i]);
		bn_free(z[i]);
		g2_free(d[i]);
		g2_free(s[i]);
	}
	g2_free(d[M]);
	g2_free(s[M]);
	for (int i = 0; i < N; i++) {
		bn_free(v[i]);
		bn_free(w[i]);
		bn_free(y[i]);
		g1_free(u[i]);
		gt_free(t[i]);
	}
	crt_free(crt);
	return code;
}

#undef M
#undef N
#define M	256			/* Number of server messages (larger). */
#define N	8			/* Number of client messages. */

static void bench(void) {
	bn_t g, n, q, r, p[M], x[M], v[N], w[N], y[N], z[M];
	g1_t u[N], ss;
	g2_t d[M + 1], s[M + 1];
	gt_t t[N];
	crt_t crt;
	int len;

	bn_null(n);
	bn_null(q);
	g1_null(ss);
	crt_null(crt);

	bn_new(n);
	bn_new(q);
	g1_new(ss);
	for (int i = 0; i < M; i++) {
		bn_null(p[i]);
		bn_null(x[i]);
		bn_null(z[i]);
		g2_null(d[i]);
		g2_null(s[i]);
		bn_new(p[i]);
		bn_new(x[i]);
		bn_new(z[i]);
		g2_new(d[i]);
		g2_new(s[i]);
	}
	g2_null(d[M]);
	g2_new(d[M]);
	g2_null(s[M]);
	g2_new(s[M]);
	for (int i = 0; i < N; i++) {
		bn_null(v[i]);
		bn_null(w[i]);
		bn_null(y[i]);
		g1_null(u[i]);
		gt_null(t[i]);
		bn_new(v[i]);
		bn_new(w[i]);
		bn_new(y[i]);
		g1_new(u[i]);
		gt_new(t[i]);
	}
	crt_new(crt);

	pc_get_ord(q);
	for (int j = 0; j < M; j++) {
		bn_rand_mod(x[j], q);
	}
	for (int j = 0; j < N; j++) {
		bn_rand_mod(y[j], q);
	}

	BENCH_RUN("cp_pbpsi_gen") {
		BENCH_ADD(cp_pbpsi_gen(q, ss, s, M));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_ask") {
		BENCH_ADD(cp_pbpsi_ask(d, r, x, s, M));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_ans") {
		BENCH_ADD(cp_pbpsi_ans(t, u, ss, d[0], y, N));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_int") {
		BENCH_ADD(cp_pbpsi_int(z, &len, q, d, x, M, t, u, N));
	} BENCH_END;

    bn_free(q);
	bn_free(r);
	g1_free(ss);
	for (int i = 0; i < M; i++) {
		bn_free(x[i]);
		bn_free(z[i]);
		g2_free(d[i]);
		g2_free(s[i]);
	}
	g2_free(d[M]);
	g2_free(s[M]);
	for (int i = 0; i < N; i++) {
		bn_free(y[i]);
		g1_free(u[i]);
		gt_free(t[i]);
	}
}

int main(int argc, char *argv[]) {
	int m, n;
	core_init();
	if (pc_param_set_any() == RLC_OK) {
		if (test() != RLC_OK) {
			core_clean();
			return 1;
		}

		bench();
	}
	core_clean();
}
