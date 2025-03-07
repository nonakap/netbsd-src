/* Target-dependent code for NetBSD/sh.

   Copyright (C) 2002-2024 Free Software Foundation, Inc.

   Contributed by Wasabi Systems, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "gdbcore.h"
#include "regset.h"
#include "value.h"
#include "osabi.h"
#include "trad-frame.h"
#include "tramp-frame.h"
#include "frame-unwind.h"

#include "sh-tdep.h"
#include "netbsd-tdep.h"
#include "solib-svr4.h"
#include "gdbarch.h"

/* Convert a register number into an offset into a ptrace
   register structure.  */
static const struct sh_corefile_regmap regmap[] =
{
  {R0_REGNUM,      20 * 4},
  {R0_REGNUM + 1,  19 * 4},
  {R0_REGNUM + 2,  18 * 4},
  {R0_REGNUM + 3,  17 * 4},
  {R0_REGNUM + 4,  16 * 4},
  {R0_REGNUM + 5,  15 * 4},
  {R0_REGNUM + 6,  14 * 4},
  {R0_REGNUM + 7,  13 * 4},
  {R0_REGNUM + 8,  12 * 4},
  {R0_REGNUM + 9,  11 * 4},
  {R0_REGNUM + 10, 10 * 4},
  {R0_REGNUM + 11,  9 * 4},
  {R0_REGNUM + 12,  8 * 4},
  {R0_REGNUM + 13,  7 * 4},
  {R0_REGNUM + 14,  6 * 4},
  {R0_REGNUM + 15,  5 * 4},
  {PC_REGNUM,       0 * 4},
  {SR_REGNUM,       1 * 4},
  {PR_REGNUM,	    2 * 4},
  {MACH_REGNUM,	    3 * 4},
  {MACL_REGNUM,	    4 * 4},
  {GBR_REGNUM,	   21 * 4},
  {-1 /* Terminator.  */, 0}
};



#define REGSx16(base) \
  {(base),      0}, \
  {(base) +  1, 4}, \
  {(base) +  2, 8}, \
  {(base) +  3, 12}, \
  {(base) +  4, 16}, \
  {(base) +  5, 20}, \
  {(base) +  6, 24}, \
  {(base) +  7, 28}, \
  {(base) +  8, 32}, \
  {(base) +  9, 36}, \
  {(base) + 10, 40}, \
  {(base) + 11, 44}, \
  {(base) + 12, 48}, \
  {(base) + 13, 52}, \
  {(base) + 14, 56}, \
  {(base) + 15, 60}

/* Convert an FPU register number into an offset into a ptrace
   register structure.  */
static const struct sh_corefile_regmap fpregmap[] =
{
  REGSx16 (FR0_REGNUM),
  /* XXX: REGSx16(XF0_REGNUM) omitted.  */
  {FPSCR_REGNUM, 128},
  {FPUL_REGNUM,  132},
  {-1 /* Terminator.  */, 0}
};


/* From <machine/mcontext.h>.  */
static const int shnbsd_mc_reg_offset[] =
{
  (20 * 4),	/* r0 */
  (19 * 4),	/* r1 */
  (18 * 4),	/* r2 */ 
  (17 * 4),	/* r3 */ 
  (16 * 4),	/* r4 */
  (15 * 4),	/* r5 */
  (14 * 4),	/* r6 */
  (13 * 4),	/* r7 */
  (12 * 4),	/* r8 */ 
  (11 * 4),	/* r9 */
  (10 * 4),	/* r10 */
  ( 9 * 4),	/* r11 */
  ( 8 * 4),	/* r12 */
  ( 7 * 4),	/* r13 */
  ( 6 * 4),	/* r14 */
  (21 * 4),	/* r15/sp */
  ( 1 * 4),	/* pc */
  ( 5 * 4),	/* pr */
  ( 0 * 4),	/* gbr */
  -1,
  ( 4 * 4),	/* mach */
  ( 3 * 4),	/* macl */
  ( 2 * 4),	/* sr */
};

/* SH register sets.  */


static void
shnbsd_sigtramp_cache_init (const struct tramp_frame *,
			    const frame_info_ptr &,
			    struct trad_frame_cache *,
			    CORE_ADDR);

/* The siginfo signal trampoline for NetBSD/sh3 versions 2.0 and later */
static const struct tramp_frame shnbsd_sigtramp_si2 =
{
  SIGTRAMP_FRAME,
  2,
  {
    { 0x64f3, ULONGEST_MAX },			/* mov     r15,r4 */
    { 0xd002, ULONGEST_MAX },			/* mov.l   .LSYS_setcontext */
    { 0xc380, ULONGEST_MAX },			/* trapa   #-128 */
    { 0xa003, ULONGEST_MAX },			/* bra     .Lskip1 */
    { 0x0009, ULONGEST_MAX },			/* nop */
    { 0x0009, ULONGEST_MAX },			/* nop */
 /* .LSYS_setcontext */
    { 0x0134, ULONGEST_MAX }, { 0x0000, ULONGEST_MAX },     /* 0x134 */
 /* .Lskip1 */
    { 0x6403, ULONGEST_MAX },			/* mov     r0,r4 */
    { 0xd002, ULONGEST_MAX },			/* mov.l   .LSYS_exit  */
    { 0xc380, ULONGEST_MAX },			/* trapa   #-128 */
    { 0xa003, ULONGEST_MAX },			/* bra     .Lskip2 */
    { 0x0009, ULONGEST_MAX },			/* nop */
    { 0x0009, ULONGEST_MAX },			/* nop */
 /* .LSYS_exit */
    { 0x0001, ULONGEST_MAX }, { 0x0000, ULONGEST_MAX },     /* 0x1 */
/* .Lskip2 */
    { TRAMP_SENTINEL_INSN, ULONGEST_MAX }
  },
  shnbsd_sigtramp_cache_init
};

static void
shnbsd_sigtramp_cache_init (const struct tramp_frame *self,
			    const frame_info_ptr& next_frame,
			    struct trad_frame_cache *this_cache,
			    CORE_ADDR func)
{
  struct gdbarch *gdbarch = get_frame_arch (next_frame);
  // struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  int sp_regnum = gdbarch_sp_regnum (gdbarch);
  CORE_ADDR sp = get_frame_register_unsigned (next_frame, sp_regnum);
  CORE_ADDR base;
  const int *reg_offset;
  int num_regs;
  int i;

  reg_offset = shnbsd_mc_reg_offset;
  num_regs = ARRAY_SIZE (shnbsd_mc_reg_offset);
  /* SP already points at the ucontext. */
  base = sp;
  /* offsetof(ucontext_t, uc_mcontext) == 36 */
  base += 36;

  for (i = 0; i < num_regs; i++)
    if (reg_offset[i] != -1)
      trad_frame_set_reg_addr (this_cache, i, base + reg_offset[i]);

  /* Construct the frame ID using the function start.  */
  trad_frame_set_id (this_cache, frame_id_build (sp, func));
}

static void
shnbsd_init_abi (struct gdbarch_info info,
		  struct gdbarch *gdbarch)
{
  sh_gdbarch_tdep *tdep = gdbarch_tdep<sh_gdbarch_tdep> (gdbarch);
  nbsd_init_abi (info, gdbarch);

  tdep->core_gregmap = (struct sh_corefile_regmap *)regmap;
  tdep->sizeof_gregset = 88;

  tdep->core_fpregmap = (struct sh_corefile_regmap *)fpregmap;
  tdep->sizeof_fpregset = 0;	/* XXX */

  set_solib_svr4_fetch_link_map_offsets
    (gdbarch, svr4_ilp32_fetch_link_map_offsets);
  tramp_frame_prepend_unwinder (gdbarch, &shnbsd_sigtramp_si2);
}

void _initialize_shnbsd_tdep ();
void
_initialize_shnbsd_tdep ()
{
  gdbarch_register_osabi (bfd_arch_sh, 0, GDB_OSABI_NETBSD,
			  shnbsd_init_abi);
}
