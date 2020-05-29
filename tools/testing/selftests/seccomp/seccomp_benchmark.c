/*
 * Strictly speaking, this is not a test. But it can report during test
 * runs so relative performace can be measured.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define ARRAY_SIZE(a)    (sizeof(a) / sizeof(a[0]))

unsigned long long timing(clockid_t clk_id, unsigned long long samples)
{
	pid_t pid, ret;
	unsigned long long i;
	struct timespec start, finish;

	pid = getpid();
	assert(clock_gettime(clk_id, &start) == 0);
	for (i = 0; i < samples; i++) {
		ret = syscall(__NR_getpid);
		assert(pid == ret);
	}
	assert(clock_gettime(clk_id, &finish) == 0);

	i = finish.tv_sec - start.tv_sec;
	i *= 1000000000;
	i += finish.tv_nsec - start.tv_nsec;

	printf("%lu.%09lu - %lu.%09lu = %llu\n",
		finish.tv_sec, finish.tv_nsec,
		start.tv_sec, start.tv_nsec,
		i);

	return i;
}

unsigned long long calibrate(void)
{
	unsigned long long i;

	printf("Calibrating reasonable sample size...\n");

	for (i = 5; ; i++) {
		unsigned long long samples = 1 << i;

		/* Find something that takes more than 5 seconds to run. */
		if (timing(CLOCK_REALTIME, samples) / 1000000000ULL > 5)
			return samples;
	}
}

#define SECCOMP_FILTER_FLAG_BENCHMARK	(1UL << 5)

#ifndef seccomp
int seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}
#endif

int main(int argc, char *argv[])
{
	struct sock_filter filter[] = {
		BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)ARRAY_SIZE(filter),
		.filter = filter,
	};
	long ret;
	unsigned long long samples;
	unsigned long long native, filter1, filter2, no_bpf;

	if (argc > 1)
		samples = strtoull(argv[1], NULL, 0);
	else
		samples = calibrate();

	printf("Benchmarking %llu samples...\n", samples);

	/* Native call */
	native = timing(CLOCK_PROCESS_CPUTIME_ID, samples) / samples;
	printf("getpid native: %llu ns\n", native);

	ret = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	assert(ret == 0);

	/* One filter */
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	assert(ret == 0);

	filter1 = timing(CLOCK_PROCESS_CPUTIME_ID, samples) / samples;
	printf("getpid RET_ALLOW 1 filter: %llu ns\n", filter1);

	/* Two filters */
	ret = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	assert(ret == 0);

	filter2 = timing(CLOCK_PROCESS_CPUTIME_ID, samples) / samples;
	printf("getpid RET_ALLOW 2 filters: %llu ns\n", filter2);

	/* Benchmark bypass filter */
	ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_BENCHMARK, &prog);
	assert(ret == 0);

	no_bpf = timing(CLOCK_PROCESS_CPUTIME_ID, samples) / samples;
	printf("getpid BPF-less allow: %llu ns\n", no_bpf);

	/* Calculations */
	printf("Estimated total seccomp overhead for 1 filter: %llu ns\n",
		filter1 - native);

	printf("Estimated total seccomp overhead for 2 filters: %llu ns\n",
		filter2 - native);

	printf("Estimated seccomp per-filter overhead: %llu ns\n",
		filter2 - filter1);

	printf("Estimated seccomp entry overhead: %llu ns\n",
		filter1 - native - (filter2 - filter1));

	printf("Estimated BPF overhead per filter: %llu ns\n",
		filter1 - no_bpf);

	return 0;
}
