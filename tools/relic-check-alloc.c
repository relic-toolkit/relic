/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2026 RELIC Authors
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
 * Allocation-failure test of the library contexts. Each run makes the k-th
 * allocation fail, for k = 1, 2, ... until a run makes fewer than k, while
 * a scenario initializes the library, uses it in POSIX threads that exit with
 * and without core_clean(), and runs the parallel sections of two Paillier
 * decryptions. Only these steps are counted, not the key generation and the
 * encryptions, whose random inputs would change k from run to run. A run may
 * end normally, with an error returned by core_init(), or in the deliberate
 * abort for running out of memory, and anything else, such as a crash or a
 * sanitizer report, is a failure.
 *
 * Build it against a static library, with ASan and ALLOC=AUTO to test only
 * the contexts, or ALLOC=DYNAMIC to fail every allocation, for example:
 *   cmake -B build -DMULTI=OPENMP -DALLOC=AUTO -DAUSAN=on -DTESTS=0 \
 *     -DBENCH=0 -DSHLIB=off && cmake --build build -t relic_s
 *   gcc -O1 -g -fsanitize=address,undefined -fopenmp -Iinclude \
 *     -Ibuild/include tools/relic-check-alloc.c build/lib/librelic_s.a \
 *     -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=posix_memalign \
 *     -lpthread -o check-alloc && ./check-alloc
 *
 * The optional arguments are the first and last k to try, to split a long
 * sweep across processes.
 *
 * Only allocations made by the library and this file are failed, not those of
 * the C, threading or OpenMP runtimes, which are linked dynamically.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>

#include "relic.h"

/** Number of allocations made so far. */
static unsigned long count = 0;

/** Index of the allocation to fail, or zero for none. */
static unsigned long fail = 0;

/** Flag to count allocations. */
static int armed = 1;

void *__real_malloc(size_t size);
void *__real_calloc(size_t n, size_t size);
void *__real_realloc(void *ptr, size_t size);
int __real_posix_memalign(void **ptr, size_t align, size_t size);

/**
 * Counts an allocation and decides whether it fails.
 *
 * @return 1 if the allocation must fail, 0 otherwise.
 */
static int fails(void) {
	if (!__atomic_load_n(&armed, __ATOMIC_RELAXED)) {
		return 0;
	}
	return __atomic_add_fetch(&count, 1, __ATOMIC_RELAXED) == fail;
}

void *__wrap_malloc(size_t size) {
	return fails() ? NULL : __real_malloc(size);
}

void *__wrap_calloc(size_t n, size_t size) {
	return fails() ? NULL : __real_calloc(n, size);
}

void *__wrap_realloc(void *ptr, size_t size) {
	return fails() ? NULL : __real_realloc(ptr, size);
}

int __wrap_posix_memalign(void **ptr, size_t align, size_t size) {
	return fails() ? 12 : __real_posix_memalign(ptr, align, size);
}

/**
 * Uses the library in a thread, which exits with or without core_clean().
 *
 * @param[in] arg			- non-NULL to call core_clean() before exiting.
 * @return NULL.
 */
static void *thread(void *arg) {
	bn_t a;

	if (core_init() != RLC_OK) {
		/* A failed initialization leaves no context to use or clean. */
		return NULL;
	}
	bn_null(a);
	RLC_TRY {
		bn_new(a);
		bn_rand(a, RLC_POS, 128);
		bn_sqr(a, a);
	}
	RLC_FINALLY {
		bn_free(a);
	}
	if (arg != NULL) {
		core_clean();
	}
	return NULL;
}

/**
 * Initializes the library, starts the threads and decrypts with Paillier.
 *
 * @return 0 if the run ended normally.
 */
static int scenario(void) {
	pthread_t t[2];
	bn_t pub, m, c, d;
	phpe_t prv;
	int code = 0;

	if (core_init() != RLC_OK) {
		core_clean();
		return 0;
	}
	if (pthread_create(&t[0], NULL, thread, NULL) == 0) {
		pthread_join(t[0], NULL);
	}
	if (pthread_create(&t[1], NULL, thread, (void *)1) == 0) {
		pthread_join(t[1], NULL);
	}

	bn_null_all(pub, m, c, d);
	phpe_null(prv);

	RLC_TRY {
		bn_new_all(pub, m, c, d);
		phpe_new(prv);

		/* Decrypt twice, so a second section reuses the thread contexts. */
		armed = 0;
		if (cp_phpe_gen(pub, prv, 512) == RLC_OK) {
			for (int j = 0; j < 2; j++) {
				armed = 0;
				bn_rand_mod(m, pub);
				if (cp_phpe_enc(c, m, pub) != RLC_OK) {
					code = 1;
				}
				armed = 1;
				if (cp_phpe_dec(d, c, prv) != RLC_OK ||
						bn_cmp(m, d) != RLC_EQ) {
					code = 1;
				}
			}
		}
		armed = 1;
	}
	RLC_FINALLY {
		bn_free_all(pub, m, c, d);
		phpe_free(prv);
	}
	core_clean();
	return code;
}

/**
 * Runs the scenario in a new process that fails the k-th allocation.
 *
 * @param[in] self			- the path of this program.
 * @param[in] k				- the allocation to fail.
 * @param[out] n			- the number of allocations made.
 * @param[out] out			- the error output of the run.
 * @param[in] len			- the size of the error output buffer.
 * @return the wait status of the run.
 */
static int run(const char *self, unsigned long k, unsigned long *n,
		char *out, size_t len) {
	char arg[32], drain[256];
	int fd[2], status;
	size_t l = 0;
	ssize_t r;
	pid_t pid;

	snprintf(arg, sizeof(arg), "%lu", k);
	if (pipe(fd) != 0 || (pid = fork()) < 0) {
		perror("fork");
		exit(2);
	}
	if (pid == 0) {
		dup2(fd[1], STDERR_FILENO);
		dup2(fd[1], STDOUT_FILENO);
		close(fd[0]);
		setenv("RLC_ALLOC_FAIL", arg, 1);
		execl(self, self, (char *)NULL);
		_exit(127);
	}
	close(fd[1]);
	while (l + 1 < len && (r = read(fd[0], out + l, len - l - 1)) > 0) {
		l += r;
	}
	/* Drain what does not fit, so the run never blocks on a full pipe. */
	while (read(fd[0], drain, sizeof(drain)) > 0);
	out[l] = '\0';
	close(fd[0]);
	waitpid(pid, &status, 0);
	*n = 0;
	char *p = strstr(out, "ALLOCATIONS ");
	if (p != NULL) {
		*n = strtoul(p + 12, NULL, 10);
	}
	return status;
}

int main(int argc, char *argv[]) {
	static char out[1 << 16];
	unsigned long k, n, last, ok = 0, err = 0, fatal = 0, bad = 0;
	char *env = getenv("RLC_ALLOC_FAIL");
	int status;

	if (env != NULL) {
		/* A single run, started by the driver below. */
		fail = strtoul(env, NULL, 10);
		status = scenario();
		fprintf(stderr, "ALLOCATIONS %lu\n", count);
		return status;
	}

	k = (argc > 1 ? strtoul(argv[1], NULL, 10) : 1);
	last = (argc > 2 ? strtoul(argv[2], NULL, 10) : (unsigned long)-1);
	for (; k <= last; k++) {
		status = run(argv[0], k, &n, out, sizeof(out));
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && n > 0 && n < k) {
			/* The run made fewer than k allocations, so none failed. */
			break;
		}
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			if (strstr(out, "ERROR") != NULL) {
				err++;
			} else {
				ok++;
			}
		} else if (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT &&
				strstr(out, "FATAL ERROR") != NULL &&
				strstr(out, "Sanitizer") == NULL) {
			fatal++;
		} else {
			bad++;
			printf("k = %lu: ", k);
			if (WIFEXITED(status)) {
				printf("exit %d\n", WEXITSTATUS(status));
			} else {
				printf("signal %d\n", WTERMSIG(status));
			}
			printf("%.2000s\n", out);
		}
	}
	printf("%lu allocations: %lu handled, %lu with an error, %lu fatal, "
			"%lu failed\n", ok + err + fatal + bad, ok, err, fatal, bad);
	return bad != 0;
}
