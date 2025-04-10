/* $NetBSD: t_futex_ops.c,v 1.14 2025/03/05 12:02:00 riastradh Exp $ */

/*-
 * Copyright (c) 2019, 2020 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__COPYRIGHT("@(#) Copyright (c) 2019, 2020\
 The NetBSD Foundation, inc. All rights reserved.");
__RCSID("$NetBSD: t_futex_ops.c,v 1.14 2025/03/05 12:02:00 riastradh Exp $");

#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <atomic.h>
#include <errno.h>
#include <lwp.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <limits.h>
#include <sched.h>
#include <unistd.h>

#include <atf-c.h>

#include <libc/include/futex_private.h>

#include "h_macros.h"

#define	LOAD(x)		(*(volatile int *)(x))
#define	STORE(x, y)	*(volatile int *)(x) = (y)

#if 0
#define	DPRINTF(x)	printf x
#else
#define	DPRINTF(x)	__nothing
#endif

#define	STACK_SIZE	65536

static volatile int futex_word;
static volatile int futex_word1;

static volatile unsigned int nlwps_running;

struct lwp_data {
	ucontext_t	context;
	void		(*func)(void *);
	void		*stack_base;
	lwpid_t		lwpid;
	pid_t		child;
	lwpid_t		threadid;
	int		wait_op;
	int		op_flags;
	int		bitset;
	volatile int	*futex_ptr;
	volatile int	*error_ptr;
	int		block_val;

	void		(*exit_func)(void);

	int		futex_error;
};

#define	WAITER_LWP0		0
#define	WAITER_LWP1		1
#define	WAITER_LWP2		2
#define	WAITER_LWP3		3
#define	WAITER_LWP4		4
#define	WAITER_LWP5		5
#define	NLWPS			6

struct lwp_data lwp_data[NLWPS];

static const char *bs_path = "t_futex_ops_backing_store";
static int bs_fd = -1;
static int *bs_addr = MAP_FAILED;
static void *bs_source_buffer = NULL;
static void *bs_verify_buffer = NULL;
static long bs_pagesize;

static void
create_lwp_waiter(struct lwp_data *d)
{
	RL(_lwp_create(&d->context, 0, &d->lwpid));
}

static void
exit_lwp_waiter(void)
{
	_lwp_exit();
}

static void
reap_lwp_waiter(struct lwp_data *d)
{
	RL(_lwp_wait(d->lwpid, NULL));
}

static void
create_proc_waiter(struct lwp_data *d)
{
	pid_t pid;

	RL(pid = fork());
	if (pid == 0) {
		(*d->func)(d);
		_exit(666);		/* backstop */
	} else
		d->child = pid;
}

static void
exit_proc_waiter(void)
{
	_exit(0);
}

static void
reap_proc_waiter(struct lwp_data *d)
{
	pid_t pid;
	int status;

	RL(pid = waitpid(d->child, &status, 0));
	ATF_CHECK_EQ_MSG(pid, d->child,
	    "pid=%lld d->child=%lld", (long long)pid, (long long)d->child);
	ATF_CHECK_MSG(WIFEXITED(status), "status=0x%x", status);
	ATF_CHECK_EQ_MSG(WEXITSTATUS(status), 0, "status=0x%x", status);
}

static void
setup_lwp_context(struct lwp_data *d, void (*func)(void *))
{

	memset(d, 0, sizeof(*d));
	REQUIRE_LIBC(d->stack_base = mmap(NULL, STACK_SIZE,
		PROT_READ | PROT_WRITE, MAP_ANON | MAP_STACK | MAP_PRIVATE,
		-1, 0),
	    MAP_FAILED);
	_lwp_makecontext(&d->context, func, d, NULL, d->stack_base,
	    STACK_SIZE);
	d->threadid = 0;
	d->func = func;
}

static void
simple_test_waiter_lwp(void *arg)
{
	struct lwp_data *d = arg;

	d->threadid = _lwp_self();

	membar_producer();
	atomic_inc_uint(&nlwps_running);
	membar_sync();

	if (__futex(d->futex_ptr, d->wait_op | d->op_flags,
		d->block_val, NULL, NULL, 0, d->bitset) == -1) {
		d->futex_error = errno;
		membar_sync();
		atomic_dec_uint(&nlwps_running);
		_lwp_exit();
	} else {
		d->futex_error = 0;
	}

	membar_sync();
	atomic_dec_uint(&nlwps_running);

	_lwp_exit();
}

static bool
verify_zero_bs(void)
{
	ssize_t nread;

	if (bs_verify_buffer == NULL) {
		REQUIRE_LIBC(bs_verify_buffer = malloc(bs_pagesize), NULL);
	}

	RL(nread = pread(bs_fd, bs_verify_buffer, bs_pagesize, 0));
	ATF_REQUIRE_EQ_MSG(nread, bs_pagesize, "nread=%zu bs_pagesize=%lu",
	    nread, bs_pagesize);

	return (memcmp(bs_verify_buffer, bs_source_buffer, bs_pagesize) == 0);
}

static void
create_bs(int map_flags)
{
	ssize_t nwrit;

	bs_pagesize = sysconf(_SC_PAGESIZE);
	ATF_REQUIRE_MSG(bs_pagesize > 0, "bs_pagesize=%ld", bs_pagesize);

	if ((map_flags & (MAP_FILE | MAP_ANON)) == MAP_FILE) {
		REQUIRE_LIBC(bs_source_buffer = calloc(1, bs_pagesize), NULL);

		RL(bs_fd = open(bs_path, O_RDWR | O_CREAT | O_EXCL, 0644));
		RL(nwrit = pwrite(bs_fd, bs_source_buffer, bs_pagesize, 0));
		ATF_REQUIRE_EQ_MSG(nwrit, bs_pagesize,
		    "nwrit=%zu bs_pagesize=%lu", nwrit, bs_pagesize);
		ATF_REQUIRE(verify_zero_bs());
	}

	REQUIRE_LIBC(bs_addr = mmap(NULL, bs_pagesize, PROT_READ | PROT_WRITE,
		map_flags | MAP_HASSEMAPHORE, bs_fd, 0),
	    MAP_FAILED);
}

static void
cleanup_bs(void)
{

	if (bs_fd != -1) {
		(void) close(bs_fd);
		bs_fd = -1;
		(void) unlink(bs_path);
	}
	if (bs_source_buffer != NULL) {
		free(bs_source_buffer);
		bs_source_buffer = NULL;
	}
	if (bs_verify_buffer != NULL) {
		free(bs_verify_buffer);
		bs_verify_buffer = NULL;
	}
	if (bs_addr != MAP_FAILED) {
		munmap(bs_addr, bs_pagesize);
		bs_addr = MAP_FAILED;
	}
}

static void
do_cleanup(void)
{
	int i;

	for (i = 0; i < NLWPS; i++) {
		struct lwp_data *d = &lwp_data[i];
		if (d->stack_base != NULL && d->stack_base != MAP_FAILED) {
			(void) munmap(d->stack_base, STACK_SIZE);
		}
	}
	memset(lwp_data, 0, sizeof(lwp_data));
	STORE(&futex_word, 0);
	STORE(&futex_word1, 0);
	nlwps_running = 0;

	cleanup_bs();
}

/*****************************************************************************/

static void
wait_wake_test_waiter_lwp(void *arg)
{
	struct lwp_data *d = arg;

	d->threadid = _lwp_self();

	STORE(d->futex_ptr, 1);
	membar_sync();

	/* This will block because *futex_ptr == 1. */
	if (__futex(d->futex_ptr, FUTEX_WAIT | d->op_flags,
		1, NULL, NULL, 0, 0) == -1) {
		STORE(d->error_ptr, errno);
		(*d->exit_func)();
	} else {
		STORE(d->error_ptr, 0);
	}

	do {
		membar_sync();
		sleep(1);
	} while (LOAD(d->futex_ptr) != 0);

	STORE(d->futex_ptr, 2);
	membar_sync();

	do {
		membar_sync();
		sleep(1);
	} while (LOAD(d->futex_ptr) != 3);

	/* This will not block because futex_word != 666. */
	if (__futex(d->futex_ptr, FUTEX_WAIT | d->op_flags,
		666, NULL, NULL, 0, 0) == -1) {
		/* This SHOULD be EAGAIN. */
		STORE(d->error_ptr, errno);
	}

	STORE(d->futex_ptr, 4);
	membar_sync();

	(*d->exit_func)();
}

static void
do_futex_wait_wake_test(volatile int *futex_ptr, volatile int *error_ptr,
    void (*create_func)(struct lwp_data *),
    void (*exit_func)(void),
    void (*reap_func)(struct lwp_data *),
    int flags)
{
	struct lwp_data *wlwp = &lwp_data[WAITER_LWP0];
	int tries;
	int n;

	if (error_ptr == NULL)
		error_ptr = &wlwp->futex_error;

	if (create_func == NULL)
		create_func = create_lwp_waiter;
	if (exit_func == NULL)
		exit_func = exit_lwp_waiter;
	if (reap_func == NULL)
		reap_func = reap_lwp_waiter;

	setup_lwp_context(wlwp, wait_wake_test_waiter_lwp);

	DPRINTF(("futex_basic_wait_wake: testing with flags 0x%x\n", flags));
	wlwp->op_flags = flags;
	wlwp->error_ptr = error_ptr;
	STORE(error_ptr, -1);
	wlwp->futex_ptr = futex_ptr;
	STORE(futex_ptr, 0);
	wlwp->exit_func = exit_func;
	membar_sync();

	DPRINTF(("futex_basic_wait_wake: creating watier LWP\n"));
	(*create_func)(wlwp);

	DPRINTF(("futex_basic_wait_wake: waiting for LWP %d to enter futex\n",
	    wlwp->lwpid));
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (LOAD(futex_ptr) == 1)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG((n = LOAD(futex_ptr)), 1, "LOAD(futex_ptr)=%d", n);

	/*
	 * If the LWP is blocked in the futex, it will not have yet
	 * modified *error_ptr.
	 */
	DPRINTF(("futex_basic_wait_wake: checking for successful wait (%d)\n",
	    LOAD(error_ptr)));
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (LOAD(error_ptr) == -1)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG((n = LOAD(error_ptr)), -1, "error=%d", n);

	/* Make sure invalid #wakes in rejected. */
	ATF_REQUIRE_ERRNO(EINVAL,
	    __futex(futex_ptr, FUTEX_WAKE | flags,
		-1, NULL, NULL, 0, 0) == -1);

	DPRINTF(("futex_basic_wait_wake: waking 1 waiter\n"));
	RL(n = __futex(futex_ptr, FUTEX_WAKE | flags, 1, NULL, NULL, 0, 0));
	ATF_REQUIRE_EQ_MSG(n, 1, "n=%d wakeups", n);

	DPRINTF(("futex_basic_wait_wake: checking for successful wake (%d)\n",
	    LOAD(error_ptr)));
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (LOAD(error_ptr) == 0)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG((n = LOAD(error_ptr)), 0, "error=%d", n);

	STORE(futex_ptr, 0);
	membar_sync();

	DPRINTF(("futex_basic_wait_wake: waiting for LWP to advance (2)\n"));
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (LOAD(futex_ptr) == 2)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG((n = LOAD(futex_ptr)), 2, "LOAD(futex_ptr)=%d", n);

	STORE(futex_ptr, 3);
	membar_sync();

	DPRINTF(("futex_basic_wait_wake: waiting for LWP to advance (4)\n"));
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (LOAD(futex_ptr) == 4)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG((n = LOAD(futex_ptr)), 4, "error=%d", n);

	DPRINTF(("futex_basic_wait_wake: checking for expected EGAIN\n"));
	ATF_REQUIRE_EQ_MSG((n = LOAD(error_ptr)), EAGAIN, "error=%d", n);

	DPRINTF(("futex_basic_wait_wake: reaping LWP %d\n", wlwp->lwpid));
	(*reap_func)(wlwp);
}

ATF_TC_WITH_CLEANUP(futex_basic_wait_wake_private);
ATF_TC_HEAD(futex_basic_wait_wake_private, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests basic futex WAIT + WAKE operations (PRIVATE)");
}
ATF_TC_BODY(futex_basic_wait_wake_private, tc)
{
	do_futex_wait_wake_test(&futex_word, NULL,
	    NULL, NULL, NULL,
	    FUTEX_PRIVATE_FLAG);
}
ATF_TC_CLEANUP(futex_basic_wait_wake_private, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_basic_wait_wake_shared);
ATF_TC_HEAD(futex_basic_wait_wake_shared, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests basic futex WAIT + WAKE operations (SHARED)");
}
ATF_TC_BODY(futex_basic_wait_wake_shared, tc)
{
	do_futex_wait_wake_test(&futex_word, NULL,
	    NULL, NULL, NULL,
	    0);
}
ATF_TC_CLEANUP(futex_basic_wait_wake_shared, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_anon_bs_private);
ATF_TC_HEAD(futex_wait_wake_anon_bs_private, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT + WAKE operations (MAP_ANON + PRIVATE)");
}
ATF_TC_BODY(futex_wait_wake_anon_bs_private, tc)
{
	create_bs(MAP_ANON | MAP_PRIVATE);
	do_futex_wait_wake_test(&bs_addr[0], NULL,
	    NULL, NULL, NULL,
	    FUTEX_PRIVATE_FLAG);
}
ATF_TC_CLEANUP(futex_wait_wake_anon_bs_private, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_anon_bs_shared);
ATF_TC_HEAD(futex_wait_wake_anon_bs_shared, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT + WAKE operations (MAP_ANON + SHARED)");
}
ATF_TC_BODY(futex_wait_wake_anon_bs_shared, tc)
{
	create_bs(MAP_ANON | MAP_PRIVATE);
	do_futex_wait_wake_test(&bs_addr[0], NULL,
	    NULL, NULL, NULL,
	    0);
}
ATF_TC_CLEANUP(futex_wait_wake_anon_bs_shared, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_file_bs_private);
ATF_TC_HEAD(futex_wait_wake_file_bs_private, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT + WAKE operations (MAP_FILE + PRIVATE)");
}
ATF_TC_BODY(futex_wait_wake_file_bs_private, tc)
{
	/*
	 * This combination (non-COW mapped file + PRIVATE futex)
	 * doesn't really make sense, but we should make sure it
	 * works as expected.
	 */
	create_bs(MAP_FILE | MAP_SHARED);
	do_futex_wait_wake_test(&bs_addr[0], NULL,
	    NULL, NULL, NULL,
	    FUTEX_PRIVATE_FLAG);
	ATF_REQUIRE(!verify_zero_bs());
}
ATF_TC_CLEANUP(futex_wait_wake_file_bs_private, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_file_bs_cow_private);
ATF_TC_HEAD(futex_wait_wake_file_bs_cow_private, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT + WAKE operations (MAP_FILE COW + PRIVATE)");
}
ATF_TC_BODY(futex_wait_wake_file_bs_cow_private, tc)
{
	create_bs(MAP_FILE | MAP_PRIVATE);
	do_futex_wait_wake_test(&bs_addr[0], NULL,
	    NULL, NULL, NULL,
	    FUTEX_PRIVATE_FLAG);
	ATF_REQUIRE(verify_zero_bs());
}
ATF_TC_CLEANUP(futex_wait_wake_file_bs_cow_private, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_file_bs_shared);
ATF_TC_HEAD(futex_wait_wake_file_bs_shared, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT + WAKE operations (MAP_FILE + SHARED)");
}
ATF_TC_BODY(futex_wait_wake_file_bs_shared, tc)
{
	create_bs(MAP_FILE | MAP_SHARED);
	do_futex_wait_wake_test(&bs_addr[0], NULL,
	    NULL, NULL, NULL,
	    0);
	ATF_REQUIRE(!verify_zero_bs());
}
ATF_TC_CLEANUP(futex_wait_wake_file_bs_shared, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_file_bs_cow_shared);
ATF_TC_HEAD(futex_wait_wake_file_bs_cow_shared, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT + WAKE operations (MAP_FILE COW + SHARED)");
}
ATF_TC_BODY(futex_wait_wake_file_bs_cow_shared, tc)
{
	/*
	 * This combination (COW mapped file + SHARED futex)
	 * doesn't really make sense, but we should make sure it
	 * works as expected.
	 */
	create_bs(MAP_FILE | MAP_PRIVATE);
	do_futex_wait_wake_test(&bs_addr[0], NULL,
	    NULL, NULL, NULL,
	    0);
	ATF_REQUIRE(verify_zero_bs());
}
ATF_TC_CLEANUP(futex_wait_wake_file_bs_cow_shared, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_anon_bs_shared_proc);
ATF_TC_HEAD(futex_wait_wake_anon_bs_shared_proc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests multiproc futex WAIT + WAKE operations (MAP_ANON + SHARED)");
}
ATF_TC_BODY(futex_wait_wake_anon_bs_shared_proc, tc)
{
	create_bs(MAP_ANON | MAP_SHARED);
	do_futex_wait_wake_test(&bs_addr[0], &bs_addr[1],
	    create_proc_waiter,
	    exit_proc_waiter,
	    reap_proc_waiter,
	    0);
}
ATF_TC_CLEANUP(futex_wait_wake_anon_bs_shared_proc, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_file_bs_shared_proc);
ATF_TC_HEAD(futex_wait_wake_file_bs_shared_proc, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests multiproc futex WAIT + WAKE operations (MAP_ANON + SHARED)");
}
ATF_TC_BODY(futex_wait_wake_file_bs_shared_proc, tc)
{
	create_bs(MAP_FILE | MAP_SHARED);
	do_futex_wait_wake_test(&bs_addr[0], &bs_addr[1],
	    create_proc_waiter,
	    exit_proc_waiter,
	    reap_proc_waiter,
	    0);
}
ATF_TC_CLEANUP(futex_wait_wake_file_bs_shared_proc, tc)
{
	do_cleanup();
}

/*****************************************************************************/

ATF_TC(futex_wait_pointless_bitset);
ATF_TC_HEAD(futex_wait_pointless_bitset, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests basic futex WAIT + WAKE operations (SHARED)");
}
ATF_TC_BODY(futex_wait_pointless_bitset, tc)
{

	futex_word = 1;
	ATF_REQUIRE_ERRNO(EINVAL,
	    __futex(&futex_word, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
		1, NULL, NULL, 0, 0) == -1);
}

static void
do_futex_wait_wake_bitset_test(int flags)
{
	struct lwp_data *wlwp0 = &lwp_data[WAITER_LWP0];
	struct lwp_data *wlwp1 = &lwp_data[WAITER_LWP1];
	int i, tries, n;

	for (i = WAITER_LWP0; i <= WAITER_LWP1; i++) {
		setup_lwp_context(&lwp_data[i], simple_test_waiter_lwp);
		lwp_data[i].op_flags = flags;
		lwp_data[i].futex_error = -1;
		lwp_data[i].bitset = __BIT(i);
		lwp_data[i].wait_op = FUTEX_WAIT_BITSET;
		lwp_data[i].futex_ptr = &futex_word;
		lwp_data[i].block_val = 1;
	}

	STORE(&futex_word, 1);
	membar_sync();

	RL(_lwp_create(&wlwp0->context, 0, &wlwp0->lwpid));
	RL(_lwp_create(&wlwp1->context, 0, &wlwp1->lwpid));

	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 2)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 2,
	    "waiters failed to start, nlwps_running=%u", nlwps_running);

	/* Ensure they're blocked. */
	ATF_REQUIRE_EQ_MSG(wlwp0->futex_error, -1, "wlwp0->futex_error=%d",
	    wlwp0->futex_error);
	ATF_REQUIRE_EQ_MSG(wlwp1->futex_error, -1, "wlwp1->futex_error=%d",
	    wlwp1->futex_error);

	/* Make sure invalid #wakes in rejected. */
	ATF_REQUIRE_ERRNO(EINVAL,
	    __futex(&futex_word, FUTEX_WAKE_BITSET | flags,
		-1, NULL, NULL, 0, 0) == -1);

	/* This should result in no wakeups because no bits are set. */
	RL(n = __futex(&futex_word, FUTEX_WAKE_BITSET | flags,
		INT_MAX, NULL, NULL, 0, 0));
	ATF_REQUIRE_EQ_MSG(n, 0, "n=%d wakeups", n);

	/* This should result in no wakeups because the wrongs bits are set. */
	RL(n = __futex(&futex_word, FUTEX_WAKE_BITSET | flags,
		INT_MAX, NULL, NULL, 0,
		~(wlwp0->bitset | wlwp1->bitset)));
	ATF_REQUIRE_EQ_MSG(n, 0, "n=%d wakeups", n);

	/* Trust, but verify. */
	sleep(1);
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 2)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 2,
	    "waiters exited unexpectedly, nlwps_running=%u", nlwps_running);

	/* Wake up the first LWP. */
	RL(n = __futex(&futex_word, FUTEX_WAKE_BITSET | flags,
		INT_MAX, NULL, NULL, 0, wlwp0->bitset));
	ATF_REQUIRE_EQ_MSG(n, 1, "n=%d wakeups", n);
	sleep(1);
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 1)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 1, "nlwps_running=%u",
	    nlwps_running);
	ATF_REQUIRE_EQ_MSG(wlwp0->futex_error, 0, "wlwp0->futex_error=%d",
	    wlwp0->futex_error);
	RL(_lwp_wait(wlwp0->lwpid, NULL));

	/* Wake up the second LWP. */
	RL(n = __futex(&futex_word, FUTEX_WAKE_BITSET | flags,
		INT_MAX, NULL, NULL, 0, wlwp1->bitset));
	ATF_REQUIRE_EQ_MSG(n, 1, "n=%d wakeups", n);
	sleep(1);
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 0)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 0, "nlwps_running=%u",
	    nlwps_running);
	ATF_REQUIRE_EQ_MSG(wlwp1->futex_error, 0, "wlwp1->futex_error=%d",
	    wlwp1->futex_error);
	RL(_lwp_wait(wlwp1->lwpid, NULL));
}

ATF_TC_WITH_CLEANUP(futex_wait_wake_bitset);
ATF_TC_HEAD(futex_wait_wake_bitset, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT_BITSET + WAKE_BITSET operations");
}
ATF_TC_BODY(futex_wait_wake_bitset, tc)
{
	do_futex_wait_wake_bitset_test(FUTEX_PRIVATE_FLAG);
}
ATF_TC_CLEANUP(futex_wait_wake_bitset, tc)
{
	do_cleanup();
}

/*****************************************************************************/

static void
do_futex_requeue_test(int flags, int op)
{
	struct lwp_data *wlwp0 = &lwp_data[WAITER_LWP0];
	struct lwp_data *wlwp1 = &lwp_data[WAITER_LWP1];
	struct lwp_data *wlwp2 = &lwp_data[WAITER_LWP2];
	struct lwp_data *wlwp3 = &lwp_data[WAITER_LWP3];
	const int good_val3 = (op == FUTEX_CMP_REQUEUE) ?   1 : 0;
	const int bad_val3  = (op == FUTEX_CMP_REQUEUE) ? 666 : 0;
	int i, tries, n;

	for (i = WAITER_LWP0; i <= WAITER_LWP3; i++) {
		setup_lwp_context(&lwp_data[i], simple_test_waiter_lwp);
		lwp_data[i].op_flags = flags;
		lwp_data[i].futex_error = -1;
		lwp_data[i].futex_ptr = &futex_word;
		lwp_data[i].block_val = 1;
		lwp_data[i].bitset = 0;
		lwp_data[i].wait_op = FUTEX_WAIT;
	}

	STORE(&futex_word, 1);
	STORE(&futex_word1, 1);
	membar_sync();

	RL(_lwp_create(&wlwp0->context, 0, &wlwp0->lwpid));
	RL(_lwp_create(&wlwp1->context, 0, &wlwp1->lwpid));
	RL(_lwp_create(&wlwp2->context, 0, &wlwp2->lwpid));
	RL(_lwp_create(&wlwp3->context, 0, &wlwp3->lwpid));

	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 4)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 4,
	    "waiters failed to start, nlwps_running=%u", nlwps_running);

	/* Ensure they're blocked. */
	ATF_REQUIRE_EQ_MSG(wlwp0->futex_error, -1, "wlwp0->futex_error=%d",
	    wlwp0->futex_error);
	ATF_REQUIRE_EQ_MSG(wlwp1->futex_error, -1, "wlwp1->futex_error=%d",
	    wlwp1->futex_error);
	ATF_REQUIRE_EQ_MSG(wlwp2->futex_error, -1, "wlwp2->futex_error=%d",
	    wlwp2->futex_error);
	ATF_REQUIRE_EQ_MSG(wlwp3->futex_error, -1, "wlwp3->futex_error=%d",
	    wlwp3->futex_error);

	/* Make sure invalid #wakes and #requeues are rejected. */
	ATF_REQUIRE_ERRNO(EINVAL,
	    __futex(&futex_word, op | flags,
		-1, NULL, &futex_word1, INT_MAX, bad_val3) == -1);

	ATF_REQUIRE_ERRNO(EINVAL,
	    __futex(&futex_word, op | flags,
		0, NULL, &futex_word1, -1, bad_val3) == -1);

	/*
	 * FUTEX 0: 4 LWPs
	 * FUTEX 1: 0 LWPs
	 */

	if (op == FUTEX_CMP_REQUEUE) {
		/* This should fail because the futex_word value is 1. */
		ATF_REQUIRE_ERRNO(EAGAIN,
		    __futex(&futex_word, op | flags,
			0, NULL, &futex_word1, INT_MAX, bad_val3) == -1);
	}

	/*
	 * FUTEX 0: 4 LWPs
	 * FUTEX 1: 0 LWPs
	 */

	/* Move all waiters from 0 to 1. */
	RL(n = __futex(&futex_word, op | flags, 0, NULL, &futex_word1,
		INT_MAX, good_val3));
	ATF_CHECK_EQ_MSG(n, 4, "n=%d woken or requeued", n);

	/*
	 * FUTEX 0: 0 LWPs
	 * FUTEX 1: 4 LWPs
	 */

	if (op == FUTEX_CMP_REQUEUE) {
		/* This should fail because the futex_word1 value is 1. */
		ATF_REQUIRE_ERRNO(EAGAIN,
		    __futex(&futex_word1, op | flags,
			1, NULL, &futex_word, 1, bad_val3) == -1);
	}

	/*
	 * FUTEX 0: 0 LWPs
	 * FUTEX 1: 4 LWPs
	 */

	/* Wake one waiter on 1, move one waiter to 0. */
	RL(n = __futex(&futex_word1, op | flags, 1, NULL, &futex_word,
		1, good_val3));
	ATF_CHECK_EQ_MSG(n, 2, "n=%d woken or requeued", n);

	/*
	 * FUTEX 0: 1 LWP
	 * FUTEX 1: 2 LWPs
	 */

	/* Wake all waiters on 0 (should be 1). */
	RL(n = __futex(&futex_word, FUTEX_WAKE | flags, INT_MAX, NULL, NULL,
		0, 0));
	ATF_CHECK_EQ_MSG(n, 1, "n=%d woken", n);

	/* Wake all waiters on 1 (should be 2). */
	RL(n = __futex(&futex_word1, FUTEX_WAKE | flags, INT_MAX, NULL, NULL,
		0, 0));
	ATF_CHECK_EQ_MSG(n, 2, "n=%d woken", n);

	/* Trust, but verify. */
	sleep(1);
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 0)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 0,
	    "waiters failed to exit, nlwps_running=%u", nlwps_running);

	RL(_lwp_wait(wlwp0->lwpid, NULL));
	RL(_lwp_wait(wlwp1->lwpid, NULL));
	RL(_lwp_wait(wlwp2->lwpid, NULL));
	RL(_lwp_wait(wlwp3->lwpid, NULL));
}

ATF_TC_WITH_CLEANUP(futex_requeue);
ATF_TC_HEAD(futex_requeue, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex REQUEUE operations");
}
ATF_TC_BODY(futex_requeue, tc)
{
	do_futex_requeue_test(FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE);
}
ATF_TC_CLEANUP(futex_requeue, tc)
{
	do_cleanup();
}

ATF_TC_WITH_CLEANUP(futex_cmp_requeue);
ATF_TC_HEAD(futex_cmp_requeue, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex CMP_REQUEUE operations");
}
ATF_TC_BODY(futex_cmp_requeue, tc)
{
	do_futex_requeue_test(FUTEX_PRIVATE_FLAG, FUTEX_CMP_REQUEUE);
}
ATF_TC_CLEANUP(futex_cmp_requeue, tc)
{
	do_cleanup();
}

ATF_TC(futex_cmp_requeue_trivial);
ATF_TC_HEAD(futex_cmp_requeue_trivial, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests trivial cases of futex CMP_REQUEUE operations");
}
ATF_TC_BODY(futex_cmp_requeue_trivial, tc)
{
	int nwoken;

	futex_word = 123;
	futex_word1 = 456;	/* should be ignored */
	ATF_CHECK_ERRNO(EAGAIN, __futex(&futex_word, FUTEX_CMP_REQUEUE,
		/*nwake*/1, NULL, &futex_word1, /*nrequeue*/1, 0) == -1);
	ATF_CHECK_ERRNO(EAGAIN, __futex(&futex_word, FUTEX_CMP_REQUEUE,
		/*nwake*/1, NULL, &futex_word1, /*nrequeue*/1, 122) == -1);
	nwoken = __futex(&futex_word, FUTEX_CMP_REQUEUE,
	    /*nwake*/1, NULL, &futex_word1, /*nrequeue*/1, 123);
	ATF_CHECK_MSG(nwoken != -1, "errno=%d (%s)", errno, strerror(errno));
	ATF_CHECK_EQ_MSG(nwoken, 0, "nwoken=%d", nwoken);
	ATF_CHECK_EQ_MSG(futex_word, 123, "futex_word=%d", futex_word);
	ATF_CHECK_EQ_MSG(futex_word1, 456, "futex_word1=%d", futex_word1);
}

/*****************************************************************************/

static void
do_futex_wake_op_op_test(int flags)
{
	int op, n;

	futex_word = 0;
	futex_word1 = 0;

	/*
	 * The op= operations should work even if there are no waiters.
	 */

	/*
	 * Because these operations use both futex addresses, exercise
	 * rejecting unaligned futex addresses here.
	 */
	op = FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_EQ, 0);
	ATF_CHECK_ERRNO(EINVAL,
	    __futex((int *)1, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op) == -1);
	ATF_CHECK_EQ_MSG(futex_word1, 0, "futex_word1=%d", futex_word1);

	ATF_CHECK_ERRNO(EINVAL,
	    __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, (int *)1, 0, op) == -1);
	ATF_CHECK_EQ_MSG(futex_word, 0, "futex_word=%d", futex_word);

	/* Check unmapped uaddr2 handling, too. */
	ATF_CHECK_ERRNO(EFAULT,
	    __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, NULL, 0, op) == -1);
	ATF_CHECK_EQ_MSG(futex_word, 0, "futex_word=%d", futex_word);

	op = FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_EQ, 0);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 1, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_ADD, 1, FUTEX_OP_CMP_EQ, 0);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_OR, 2, FUTEX_OP_CMP_EQ, 0);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	/* This should fail because of invalid shift value 32. */
	op = FUTEX_OP(FUTEX_OP_OR | FUTEX_OP_OPARG_SHIFT, 32,
	    FUTEX_OP_CMP_EQ, 0);
	ATF_CHECK_ERRNO(EINVAL,
	    __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op) == -1);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_OR | FUTEX_OP_OPARG_SHIFT, 31,
	    FUTEX_OP_CMP_EQ, 0);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, (int)0x80000002,
	    "futex_word1=0x%x", futex_word1);

	op = FUTEX_OP(FUTEX_OP_ANDN | FUTEX_OP_OPARG_SHIFT, 31,
	    FUTEX_OP_CMP_EQ, 0);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_XOR, 2, FUTEX_OP_CMP_EQ, 0);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 0, "futex_word1=%d", futex_word1);

	/*
	 * Verify oparg is sign-extended.
	 */
	futex_word1 = 0;
	op = FUTEX_OP(FUTEX_OP_SET, 0xfff, FUTEX_OP_CMP_EQ, 0);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, -1, "futex_word1=%d", futex_word1);

	futex_word1 = 0;
	op = FUTEX_OP(FUTEX_OP_SET, -1, FUTEX_OP_CMP_EQ, 0);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 0, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, -1, "futex_word1=%d", futex_word1);
}

ATF_TC_WITH_CLEANUP(futex_wake_op_op);
ATF_TC_HEAD(futex_wake_op_op, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAKE_OP OP operations");
}
ATF_TC_BODY(futex_wake_op_op, tc)
{
	do_futex_wake_op_op_test(FUTEX_PRIVATE_FLAG);
}
ATF_TC_CLEANUP(futex_wake_op_op, tc)
{
	do_cleanup();
}

static void
create_wake_op_test_lwps(int flags)
{
	int i;

	futex_word1 = 0;
	membar_sync();

	for (i = WAITER_LWP0; i <= WAITER_LWP5; i++) {
		setup_lwp_context(&lwp_data[i], simple_test_waiter_lwp);
		lwp_data[i].op_flags = flags;
		lwp_data[i].futex_error = -1;
		lwp_data[i].futex_ptr = &futex_word1;
		lwp_data[i].block_val = 0;
		lwp_data[i].bitset = 0;
		lwp_data[i].wait_op = FUTEX_WAIT;
		RL(_lwp_create(&lwp_data[i].context, 0, &lwp_data[i].lwpid));
	}

	for (i = 0; i < 5; i++) {
		membar_sync();
		if (nlwps_running == 6)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 6,
	    "waiters failed to start, nlwps_running=%u", nlwps_running);

	/* Ensure they're blocked. */
	for (i = WAITER_LWP0; i <= WAITER_LWP5; i++) {
		ATF_REQUIRE_EQ_MSG(lwp_data[i].futex_error, -1,
		    "i=%d lwp_data[i].futex_error=%d",
		    i, lwp_data[i].futex_error);
	}
}

static void
reap_wake_op_test_lwps(void)
{
	int i;

	for (i = WAITER_LWP0; i <= WAITER_LWP5; i++) {
		RL(_lwp_wait(lwp_data[i].lwpid, NULL));
	}
}

static void
do_futex_wake_op_cmp_test(int flags)
{
	int tries, op, n;

	futex_word = 0;
	membar_sync();

	/*
	 * Verify and negative and positive for each individual
	 * compare.
	 */

	create_wake_op_test_lwps(flags);

	/* #LWPs = 6 */
	futex_word1 = 0xfff;
	op = FUTEX_OP(FUTEX_OP_SET, 0, FUTEX_OP_CMP_EQ, 0xfff);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 0, "futex_word1=%d", futex_word1);

	futex_word1 = 0xfff;
	op = FUTEX_OP(FUTEX_OP_SET, 0, FUTEX_OP_CMP_EQ, -1);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 0, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_SET, 0, FUTEX_OP_CMP_EQ, 1);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 0, "futex_word1=%d", futex_word1);

	futex_word1 = -1;
	op = FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_EQ, 0xfff);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 1, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 1, "futex_word1=%d", futex_word1);

	/* #LWPs = 5 */
	op = FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_NE, 1);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 1, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_SET, 2, FUTEX_OP_CMP_NE, 2);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 1, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	/* #LWPs = 4 */
	op = FUTEX_OP(FUTEX_OP_SET, 2, FUTEX_OP_CMP_LT, 2);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_SET, 2, FUTEX_OP_CMP_LT, 3);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 1, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	/* #LWPs = 3 */
	op = FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_LE, 1);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 1, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_SET, 1, FUTEX_OP_CMP_LE, 1);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 1, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 1, "futex_word1=%d", futex_word1);

	/* #LWPs = 2 */
	op = FUTEX_OP(FUTEX_OP_SET, 3, FUTEX_OP_CMP_GT, 3);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 3, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_SET, 2, FUTEX_OP_CMP_GT, 2);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 1, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	/* #LWPs = 1 */
	op = FUTEX_OP(FUTEX_OP_SET, 3, FUTEX_OP_CMP_GE, 4);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 0, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 3, "futex_word1=%d", futex_word1);

	op = FUTEX_OP(FUTEX_OP_SET, 2, FUTEX_OP_CMP_GE, 3);
	RL(n = __futex(&futex_word, FUTEX_WAKE_OP | flags,
		0, NULL, &futex_word1, 1, op));
	ATF_CHECK_EQ_MSG(n, 1, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word1, 2, "futex_word1=%d", futex_word1);

	/* #LWPs = 0 */

	/* Trust, but verify. */
	sleep(1);
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 0)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 0,
	    "waiters failed to exit, nlwps_running=%u", nlwps_running);

	reap_wake_op_test_lwps();

	/*
	 * Verify wakes on uaddr work even if the uaddr2 comparison
	 * fails.
	 */

	create_wake_op_test_lwps(flags);

	/* #LWPs = 6 */
	ATF_CHECK_EQ_MSG(futex_word, 0, "futex_word=%d", futex_word);
	op = FUTEX_OP(FUTEX_OP_SET, 0, FUTEX_OP_CMP_EQ, 666);
	RL(n = __futex(&futex_word1, FUTEX_WAKE_OP | flags,
		INT_MAX, NULL, &futex_word, 0, op));
	ATF_CHECK_EQ_MSG(n, 6, "n=%d woken", n);
	ATF_CHECK_EQ_MSG(futex_word, 0, "futex_word=%d", futex_word);

	/* #LWPs = 0 */

	/* Trust, but verify. */
	sleep(1);
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 0)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 0,
	    "waiters failed to exit, nlwps_running=%u", nlwps_running);

	reap_wake_op_test_lwps();
}

ATF_TC_WITH_CLEANUP(futex_wake_op_cmp);
ATF_TC_HEAD(futex_wake_op_cmp, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAKE_OP CMP operations");
}
ATF_TC_BODY(futex_wake_op_cmp, tc)
{
	do_futex_wake_op_cmp_test(FUTEX_PRIVATE_FLAG);
}
ATF_TC_CLEANUP(futex_wake_op_cmp, tc)
{
	do_cleanup();
}

/*****************************************************************************/



/*****************************************************************************/

static void
do_futex_wait_timeout(bool relative, clockid_t clock)
{
	struct timespec ts;
	struct timespec deadline;
	int op = relative ? FUTEX_WAIT : FUTEX_WAIT_BITSET;

	if (clock == CLOCK_REALTIME)
		op |= FUTEX_CLOCK_REALTIME;

	RL(clock_gettime(clock, &deadline));
	deadline.tv_sec += 2;
	if (relative) {
		ts.tv_sec = 2;
		ts.tv_nsec = 0;
	} else {
		ts = deadline;
	}

	futex_word = 1;
	ATF_REQUIRE_ERRNO(ETIMEDOUT,
	    __futex(&futex_word, op | FUTEX_PRIVATE_FLAG,
		1, &ts, NULL, 0, FUTEX_BITSET_MATCH_ANY) == -1);

	/* Can't reliably check CLOCK_REALTIME in the presence of NTP. */
	if (clock != CLOCK_REALTIME) {
		RL(clock_gettime(clock, &ts));
		ATF_CHECK_MSG(ts.tv_sec >= deadline.tv_sec,
		    "ts=%lld.%09ldsec deadline=%lld.%09ldsec",
		    (long long)ts.tv_sec, ts.tv_nsec,
		    (long long)deadline.tv_sec, deadline.tv_nsec);
		ATF_CHECK_MSG((ts.tv_sec > deadline.tv_sec ||
			ts.tv_nsec >= deadline.tv_nsec),
		    "ts=%lld.%09ldsec deadline=%lld.%09ldsec",
		    (long long)ts.tv_sec, ts.tv_nsec,
		    (long long)deadline.tv_sec, deadline.tv_nsec);
	}
}

ATF_TC(futex_wait_timeout_relative);
ATF_TC_HEAD(futex_wait_timeout_relative, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT with relative timeout");
}
ATF_TC_BODY(futex_wait_timeout_relative, tc)
{
	do_futex_wait_timeout(true, CLOCK_MONOTONIC);
}

ATF_TC(futex_wait_timeout_relative_rt);
ATF_TC_HEAD(futex_wait_timeout_relative_rt, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT with relative timeout (REALTIME)");
}
ATF_TC_BODY(futex_wait_timeout_relative_rt, tc)
{
	do_futex_wait_timeout(true, CLOCK_REALTIME);
}

ATF_TC(futex_wait_timeout_deadline);
ATF_TC_HEAD(futex_wait_timeout_deadline, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT with absolute deadline");
}
ATF_TC_BODY(futex_wait_timeout_deadline, tc)
{
	do_futex_wait_timeout(false, CLOCK_MONOTONIC);
}

ATF_TC(futex_wait_timeout_deadline_rt);
ATF_TC_HEAD(futex_wait_timeout_deadline_rt, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT with absolute deadline (REALTIME)");
}
ATF_TC_BODY(futex_wait_timeout_deadline_rt, tc)
{
	do_futex_wait_timeout(false, CLOCK_REALTIME);
}

/*****************************************************************************/

static void
sig_noop(int sig __unused)
{
}

static void (*old_act)(int) = SIG_DFL;

static void
do_futex_wait_evil_unmapped(int map_flags)
{
	int i;

	create_bs(map_flags);

	REQUIRE_LIBC(signal(SIGUSR1, sig_noop), SIG_ERR);

	setup_lwp_context(&lwp_data[0], simple_test_waiter_lwp);
	lwp_data[0].op_flags = 0;
	lwp_data[0].futex_error = -1;
	lwp_data[0].futex_ptr = &bs_addr[0];
	lwp_data[0].block_val = 0;
	lwp_data[0].bitset = 0;
	lwp_data[0].wait_op = FUTEX_WAIT;
	RL(_lwp_create(&lwp_data[0].context, 0, &lwp_data[0].lwpid));

	for (i = 0; i < 5; i++) {
		membar_sync();
		if (nlwps_running == 1)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 1,
	    "waiters failed to start, nlwps_running=%u", nlwps_running);

	/* Ensure it's blocked. */
	ATF_REQUIRE_EQ_MSG(lwp_data[0].futex_error, -1,
	    "lwp_data[0].futex_error=%d", lwp_data[0].futex_error);

	/* Rudely unmap the backing store. */
	cleanup_bs();

	/* Signal the waiter so that it leaves the futex. */
	RL(_lwp_kill(lwp_data[0].threadid, SIGUSR1));

	/* Yay! No panic! */

	reap_lwp_waiter(&lwp_data[0]);
}

ATF_TC_WITH_CLEANUP(futex_wait_evil_unmapped_anon);
ATF_TC_HEAD(futex_wait_evil_unmapped_anon, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests futex WAIT while futex is unmapped - anon memory");
}
ATF_TC_BODY(futex_wait_evil_unmapped_anon, tc)
{
	do_futex_wait_evil_unmapped(MAP_ANON);
}
ATF_TC_CLEANUP(futex_wait_evil_unmapped_anon, tc)
{
	signal(SIGUSR1, old_act);
	do_cleanup();
}

/*****************************************************************************/

static int pri_min;
static int pri_max;

static void
lowpri_simple_test_waiter_lwp(void *arg)
{
	struct lwp_data *d = arg;
	struct sched_param sp;
	int policy;

	d->threadid = _lwp_self();

	RL(_sched_getparam(getpid(), d->threadid, &policy, &sp));
	policy = SCHED_RR;
	sp.sched_priority = pri_min;
	RL(_sched_setparam(getpid(), d->threadid, policy, &sp));

	simple_test_waiter_lwp(arg);
}

static void
highpri_simple_test_waiter_lwp(void *arg)
{
	struct lwp_data *d = arg;
	struct sched_param sp;
	int policy;

	d->threadid = _lwp_self();

	RL(_sched_getparam(getpid(), d->threadid, &policy, &sp));
	policy = SCHED_RR;
	sp.sched_priority = pri_max;
	RL(_sched_setparam(getpid(), d->threadid, policy, &sp));

	simple_test_waiter_lwp(arg);
}

static void
do_test_wake_highest_pri(void)
{
	lwpid_t waiter;
	int tries;
	long pri;
	int n;

	RL(pri = sysconf(_SC_SCHED_PRI_MIN));
	pri_min = (int)pri;
	RL(pri = sysconf(_SC_SCHED_PRI_MAX));
	pri_max = (int)pri;

	futex_word = 0;
	membar_sync();

	setup_lwp_context(&lwp_data[0], lowpri_simple_test_waiter_lwp);
	lwp_data[0].op_flags = FUTEX_PRIVATE_FLAG;
	lwp_data[0].futex_error = -1;
	lwp_data[0].futex_ptr = &futex_word;
	lwp_data[0].block_val = 0;
	lwp_data[0].bitset = 0;
	lwp_data[0].wait_op = FUTEX_WAIT;
	RL(_lwp_create(&lwp_data[0].context, 0, &lwp_data[0].lwpid));

	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 1)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 1,
	    "lowpri waiter failed to start, nlwps_running=%u", nlwps_running);

	/* Ensure it's blocked. */
	ATF_REQUIRE_EQ_MSG(lwp_data[0].futex_error, -1,
	    "lwp_data[0].futex_error=%d", lwp_data[0].futex_error);

	setup_lwp_context(&lwp_data[1], highpri_simple_test_waiter_lwp);
	lwp_data[1].op_flags = FUTEX_PRIVATE_FLAG;
	lwp_data[1].futex_error = -1;
	lwp_data[1].futex_ptr = &futex_word;
	lwp_data[1].block_val = 0;
	lwp_data[1].bitset = 0;
	lwp_data[1].wait_op = FUTEX_WAIT;
	RL(_lwp_create(&lwp_data[1].context, 0, &lwp_data[1].lwpid));

	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 2)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 2,
	    "highpri waiter failed to start, nlwps_running=%u", nlwps_running);

	/* Ensure it's blocked. */
	ATF_REQUIRE_EQ_MSG(lwp_data[1].futex_error, -1,
	    "lwp_data[1].futex_error=%d", lwp_data[1].futex_error);

	/* Wake the first LWP.  We should get the highpri thread. */
	RL(n = __futex(&futex_word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
		1, NULL, NULL, 0, 0));
	ATF_REQUIRE_EQ_MSG(n, 1, "n=%d woken", n);
	sleep(1);
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 1)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 1, "nlwps_running=%u",
	    nlwps_running);
	RL(_lwp_wait(0, &waiter));
	ATF_REQUIRE_EQ_MSG(waiter, lwp_data[1].threadid,
	    "waiter=%ld lwp_data[1].threadid=%ld",
	    (long)waiter, (long)lwp_data[1].threadid);

	/* Wake the second LWP.  We should get the lowpri thread. */
	RL(n = __futex(&futex_word, FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
		1, NULL, NULL, 0, 0));
	ATF_REQUIRE_EQ_MSG(n, 1, "n=%d woken", n);
	sleep(1);
	for (tries = 0; tries < 5; tries++) {
		membar_sync();
		if (nlwps_running == 0)
			break;
		sleep(1);
	}
	membar_sync();
	ATF_REQUIRE_EQ_MSG(nlwps_running, 0, "nlwps_running=%u",
	    nlwps_running);
	RL(_lwp_wait(0, &waiter));
	ATF_REQUIRE_EQ_MSG(waiter, lwp_data[0].threadid,
	    "waiter=%ld lwp_data[0].threadid=%ld",
	    (long)waiter, (long)lwp_data[0].threadid);
}

ATF_TC_WITH_CLEANUP(futex_wake_highest_pri);
ATF_TC_HEAD(futex_wake_highest_pri, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "tests that futex WAKE wakes the highest priority waiter");
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(futex_wake_highest_pri, tc)
{
	atf_tc_expect_fail("PR kern/55230");
	do_test_wake_highest_pri();
}
ATF_TC_CLEANUP(futex_wake_highest_pri, tc)
{
	do_cleanup();
}

/*****************************************************************************/

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, futex_basic_wait_wake_private);
	ATF_TP_ADD_TC(tp, futex_basic_wait_wake_shared);
	ATF_TP_ADD_TC(tp, futex_wait_wake_anon_bs_private);
	ATF_TP_ADD_TC(tp, futex_wait_wake_anon_bs_shared);
	ATF_TP_ADD_TC(tp, futex_wait_wake_file_bs_private);
	ATF_TP_ADD_TC(tp, futex_wait_wake_file_bs_shared);
	ATF_TP_ADD_TC(tp, futex_wait_wake_file_bs_cow_private);
	ATF_TP_ADD_TC(tp, futex_wait_wake_file_bs_cow_shared);

	ATF_TP_ADD_TC(tp, futex_wait_wake_anon_bs_shared_proc);
	ATF_TP_ADD_TC(tp, futex_wait_wake_file_bs_shared_proc);

	ATF_TP_ADD_TC(tp, futex_wait_pointless_bitset);
	ATF_TP_ADD_TC(tp, futex_wait_wake_bitset);

	ATF_TP_ADD_TC(tp, futex_wait_timeout_relative);
	ATF_TP_ADD_TC(tp, futex_wait_timeout_relative_rt);
	ATF_TP_ADD_TC(tp, futex_wait_timeout_deadline);
	ATF_TP_ADD_TC(tp, futex_wait_timeout_deadline_rt);

	ATF_TP_ADD_TC(tp, futex_wait_evil_unmapped_anon);

	ATF_TP_ADD_TC(tp, futex_requeue);
	ATF_TP_ADD_TC(tp, futex_cmp_requeue);
	ATF_TP_ADD_TC(tp, futex_cmp_requeue_trivial);

	ATF_TP_ADD_TC(tp, futex_wake_op_op);
	ATF_TP_ADD_TC(tp, futex_wake_op_cmp);

	ATF_TP_ADD_TC(tp, futex_wake_highest_pri);

	return atf_no_error();
}
