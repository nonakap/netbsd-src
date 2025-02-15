/*	$NetBSD: db_trace.c,v 1.7 2024/11/25 22:04:14 skrll Exp $	*/

/*-
 * Copyright (c) 2014 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas of 3am Software Foundry.
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

__RCSID("$NetBSD: db_trace.c,v 1.7 2024/11/25 22:04:14 skrll Exp $");

#include <sys/param.h>

#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <riscv/db_machdep.h>

#include <uvm/uvm_extern.h>

#include <ddb/db_user.h>
#include <ddb/db_access.h>
#include <ddb/db_command.h>
#include <ddb/db_output.h>
#include <ddb/db_variables.h>
#include <ddb/db_sym.h>
#include <ddb/db_proc.h>
#include <ddb/db_lwp.h>
#include <ddb/db_extern.h>
#include <ddb/db_interface.h>

#ifndef _KERNEL
#include <stddef.h>
#endif

#define MAXBACKTRACE	128	/* against infinite loop */
#define TRACEFLAG_LOOKUPLWP	0x00000001

#define IN_USER_VM_ADDRESS(addr)	\
	(VM_MIN_ADDRESS <= (addr) && (addr) < VM_MAX_ADDRESS)
#define IN_KERNEL_VM_ADDRESS(addr)	\
	(VM_MIN_KERNEL_ADDRESS <= (addr) && (addr) < VM_MAX_KERNEL_ADDRESS)

static bool __unused
is_lwp(void *p)
{
	lwp_t *lwp;

	for (lwp = db_lwp_first(); lwp != NULL; lwp = db_lwp_next(lwp)) {
		if (lwp == p)
			return true;
	}
	return false;
}

static const char *
getlwpnamebysp(uint64_t sp)
{
#if defined(_KERNEL)
	lwp_t *lwp;

	for (lwp = db_lwp_first(); lwp != NULL; lwp = db_lwp_next(lwp)) {
		uint64_t uarea = uvm_lwp_getuarea(lwp);
		if ((uarea <= sp) && (sp < (uarea + USPACE))) {
			return lwp->l_name;
		}
	}
#endif
	return "unknown";
}

static void
pr_traceaddr(const char *prefix, uint64_t frame, uint64_t pc, int flags,
    void (*pr)(const char *, ...) __printflike(1, 2))
{
	db_expr_t offset;
	db_sym_t sym;
	const char *name;

	sym = db_search_symbol(pc, DB_STGY_ANY, &offset);
	if (sym != DB_SYM_NULL) {
		db_symbol_values(sym, &name, NULL);

		if (flags & TRACEFLAG_LOOKUPLWP) {
			(*pr)("%s %016" PRIx64 " %s %s() at %016" PRIx64,
			    prefix, frame, getlwpnamebysp(frame), name, pc);
		} else {
			(*pr)("%s %016" PRIx64 " %s() at %016" PRIx64 " ",
			    prefix, frame, name, pc);
		}
		db_printsym(pc, DB_STGY_PROC, pr);
		(*pr)("\n");
	} else {
		if (flags & TRACEFLAG_LOOKUPLWP) {
			(*pr)("%s %016" PRIx64 " %s ?() at %016" PRIx64 "\n",
			    prefix, frame, getlwpnamebysp(frame), pc);
		} else {
			(*pr)("%s %016" PRIx64 " ?() at %016" PRIx64 "\n", prefix, frame, pc);
		}
	}
}

void
db_stack_trace_print(db_expr_t addr, bool have_addr, db_expr_t count,
    const char *modif, void (*pr)(const char *, ...) __printflike(1, 2))
{
	vaddr_t ra, fp, lastra, lastfp;
	struct trapframe *tf = NULL;
	int flags = 0;
	bool trace_user = false;
	bool trace_thread = false;
	bool trace_lwp = false;

	pr("have_addr: %s\n", have_addr ? "true" : "false");
	if (have_addr)
		pr("addr: %lx\n", addr);
	pr("count: %ld\n", count);
	pr("modif: %s\n", modif);

	for (; *modif != '\0'; modif++) {
		switch (*modif) {
		case 'a':
			trace_lwp = true;
			trace_thread = false;
			break;
		case 'l':
			break;
		case 't':
			trace_thread = true;
			trace_lwp = false;
			break;
		case 'u':
			trace_user = true;
			break;
		case 'x':
			flags |= TRACEFLAG_LOOKUPLWP;
			break;
		default:
			pr("usage: bt[/ulx] [frame-address][,count]\n");
			pr("       bt/t[ulx] [pid][,count]\n");
			pr("       bt/a[ulx] [lwpaddr][,count]\n");
			pr("\n");
			pr("       /x      reverse lookup lwp name from sp\n");
			return;
		}
	}

#if defined(_KERNEL)
	if (!have_addr) {
		if (trace_lwp) {
			addr = (db_expr_t)curlwp;
		} else if (trace_thread) {
			addr = curlwp->l_proc->p_pid;
		} else {
			tf = DDB_REGS;
		}
	}
#endif

	if (trace_thread) {
		proc_t *pp;

		if ((pp = db_proc_find((pid_t)addr)) == 0) {
			(*pr)("trace: pid %d: not found\n", (int)addr);
			return;
		}
		db_read_bytes((db_addr_t)pp + offsetof(proc_t, p_lwps.lh_first),
		    sizeof(addr), (char *)&addr);
		trace_thread = false;
		trace_lwp = true;
	}

#if 0
	/* "/a" is abbreviated? */
	if (!trace_lwp && is_lwp(addr))
		trace_lwp = true;
#endif

	if (trace_lwp) {
		proc_t p;
		struct lwp l;

		db_read_bytes(addr, sizeof(l), (char *)&l);
		db_read_bytes((db_addr_t)l.l_proc, sizeof(p), (char *)&p);

#if defined(_KERNEL)
		if (addr == (db_expr_t)curlwp) {
			fp = (register_t)&DDB_REGS->tf_s0; /* s0 = fp */
			tf = DDB_REGS;
			(*pr)("trace: pid %d lid %d (curlwp) at tf %p\n",
			    p.p_pid, l.l_lid, tf);
		} else
#endif
		{
			tf = l.l_md.md_ktf;
			db_read_bytes((db_addr_t)&tf->tf_s0, sizeof(fp), (char *)&fp);
			(*pr)("trace: pid %d lid %d at tf %p\n",
			    p.p_pid, l.l_lid, tf);
		}
	} else if (tf == NULL) {
		fp = addr;
		pr("trace fp %016" PRIxVADDR "\n", fp);
	} else {
		pr("trace tf %p\n", tf);
	}

	if (count > MAXBACKTRACE)
		count = MAXBACKTRACE;

	if (tf != NULL) {
#if defined(_KERNEL)
		(*pr)("---- trapframe %p (%zu bytes) ----\n",
		    tf, sizeof(*tf));
		dump_trapframe(tf, pr);
		(*pr)("------------------------"
		      "------------------------\n");

#endif
		lastfp = lastra = ra = fp = 0;
		db_read_bytes((db_addr_t)&tf->tf_ra, sizeof(ra), (char *)&ra);
		db_read_bytes((db_addr_t)&tf->tf_s0, sizeof(fp), (char *)&fp);

		pr_traceaddr("fp", fp, ra - 4, flags, pr);
	}
	for (; (count > 0) && (fp != 0); count--) {

		lastfp = fp;
		fp = ra = 0;
		/*
		 * normal stack frame
		 *  fp[-1]  saved fp(s0) value
		 *  fp[-2]  saved ra value
		 */
		db_read_bytes(lastfp - 1 * sizeof(register_t), sizeof(ra), (char *)&ra);
		db_read_bytes(lastfp - 2 * sizeof(register_t), sizeof(fp), (char *)&fp);

		if (!trace_user && (IN_USER_VM_ADDRESS(ra) || IN_USER_VM_ADDRESS(fp)))
			break;
#if defined(_KERNEL)
		extern char exception_kernexit[];

		if (((char *)ra == (char *)exception_kernexit)) {

			tf = (struct trapframe *)lastfp;

			lastra = ra;
			ra = fp = 0;
			db_read_bytes((db_addr_t)&tf->tf_pc, sizeof(ra), (char *)&ra);
			db_read_bytes((db_addr_t)&tf->tf_s0, sizeof(fp), (char *)&fp);

			pr_traceaddr("tf", (db_addr_t)tf, lastra, flags, pr);

			(*pr)("---- trapframe %p (%zu bytes) ----\n",
			    tf, sizeof(*tf));
			dump_trapframe(tf, pr);
			(*pr)("------------------------"
			      "------------------------\n");
			if (ra == 0)
				break;
			tf = NULL;

			if (!trace_user && IN_USER_VM_ADDRESS(ra))
				break;

			pr_traceaddr("fp", fp, ra, flags, pr);

		} else
#endif
		{
			pr_traceaddr("fp", fp, ra - 4, flags, pr);
		}
	}
}
