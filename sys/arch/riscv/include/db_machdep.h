/* $NetBSD: db_machdep.h,v 1.13 2024/11/25 22:04:14 skrll Exp $ */

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

#ifndef	_RISCV_DB_MACHDEP_H_
#define	_RISCV_DB_MACHDEP_H_

#include <riscv/frame.h>

#ifndef _KERNEL
#include <stdbool.h>
#endif /* _KERNEL */

#define	DB_ELF_SYMBOLS

typedef	vaddr_t		db_addr_t;	/* address - unsigned */
#define	DDB_EXPR_FMT	"l"		/* expression is long */
typedef	long		db_expr_t;	/* expression - signed */

typedef struct trapframe db_regs_t;

extern const uint32_t cpu_Debugger_insn[];
extern const uint32_t cpu_Debugger_ret[];
extern db_regs_t ddb_regs;
#define	DDB_REGS	(&ddb_regs)

#define	PC_REGS(tf)	((tf)->tf_pc)

#define	PC_ADVANCE(tf) do {						       \
	if (db_get_value((tf)->tf_pc, sizeof(uint32_t), false) == BKPT_INST)   \
		(tf)->tf_pc += BKPT_SIZE;				       \
} while(0)

/* Similar to PC_ADVANCE(), except only advance on cpu_Debugger()'s bpt */
#define	PC_BREAK_ADVANCE(tf) do {					       \
	if ((tf)->tf_pc == (register_t)cpu_Debugger_insn)		       \
		(tf)->tf_pc = (register_t)cpu_Debugger_ret;		       \
} while(0)

#define	BKPT_ADDR(addr)		(addr)			/* breakpoint address */
#define	BKPT_INST		0x00100073
#define	BKPT_SIZE		(sizeof(uint32_t))	/* size of bkpt inst */
#define	BKPT_SET(inst, addr)	(BKPT_INST)

/*
 * XXX with the C extension there's also a 16-bit-wide breakpoint
 * instruction, the idea being that you use it when inserting a
 * breakpoint into a stream of 16-bit instructions, but it looks like
 * MI ddb can't cope with having two sizes :-(
 */
#if 0
#define	BKPT_INST_2	0x9002
#define	BKPT_SIZE_2	(sizeof(uint16_t))
#endif

#define	IS_BREAKPOINT_TRAP(type, code)	((type) == CAUSE_BREAKPOINT)
#define	IS_WATCHPOINT_TRAP(type, code)	(0)

/*
 * Interface to disassembly
 */
db_addr_t	db_disasm_insn(uint32_t, db_addr_t, bool);


/*
 * Entrypoints to DDB for kernel, keyboard drivers, init hook
 */
void 	kdb_kbd_trap(db_regs_t *);
int 	kdb_trap(int, db_regs_t *);

/*
 * Constants for KGDB.
 */
typedef	register_t	kgdb_reg_t;
#define	KGDB_NUMREGS	90
#define	KGDB_BUFLEN	1024

/*
 * RISC-V harts have no hardware single-step.
 */
#define	SOFTWARE_SSTEP

#define	inst_trap_return(ins)	((ins)&0)

bool	inst_branch(uint32_t inst);
bool	inst_call(uint32_t inst);
bool	inst_return(uint32_t inst);
bool	inst_load(uint32_t inst);
bool	inst_store(uint32_t inst);
bool	inst_unconditional_flow_transfer(uint32_t inst);
db_addr_t branch_taken(uint32_t inst, db_addr_t pc, db_regs_t *regs);
db_addr_t next_instr_address(db_addr_t pc, bool bd);

bool ddb_running_on_this_cpu_p(void);
bool ddb_running_on_any_cpu_p(void);
void db_resume_others(void);

/*
 * We have machine-dependent commands.
 */
#define	DB_MACHINE_COMMANDS

void dump_trapframe(const struct trapframe *, void (*)(const char *, ...) __printflike(1, 2));

#endif	/* _RISCV_DB_MACHDEP_H_ */
