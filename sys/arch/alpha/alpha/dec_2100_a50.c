/* $NetBSD: dec_2100_a50.c,v 1.71 2025/03/09 01:06:41 thorpej Exp $ */

/*
 * Copyright (c) 1995, 1996, 1997 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Author: Chris G. Demetriou
 *
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */
/*
 * Additional Copyright (c) 1997 by Matthew Jacob for NASA/Ames Research Center
 */

#include <sys/cdefs.h>			/* RCS ID & Copyright macro defns */

__KERNEL_RCSID(0, "$NetBSD: dec_2100_a50.c,v 1.71 2025/03/09 01:06:41 thorpej Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/lwp.h>

#include <machine/rpb.h>
#include <machine/alpha.h>
#include <machine/autoconf.h>
#include <machine/cpuconf.h>
#include <machine/logout.h>

#include <dev/pci/pcivar.h>

#include <alpha/pci/apecsreg.h>
#include <alpha/pci/apecsvar.h>

void dec_2100_a50_init(void);
static void dec_2100_a50_cons_init(void);
static void dec_2100_a50_device_register(device_t, void *);

static void dec_2100_a50_mcheck_handler
(unsigned long, struct trapframe *, unsigned long, unsigned long);

static void dec_2100_a50_mcheck(unsigned long, unsigned long,
				     unsigned long, struct trapframe *);


const struct alpha_variation_table dec_2100_a50_variations[] = {
	{ SV_ST_AVANTI,	"AlphaStation 400 4/233 (\"Avanti\")" },
	{ SV_ST_MUSTANG2_4_166, "AlphaStation 200 4/166 (\"Mustang II\")" },
	{ SV_ST_MUSTANG2_4_233, "AlphaStation 200 4/233 (\"Mustang II\")" },
	{ SV_ST_AVANTI_4_266, "AlphaStation 250 4/266" },
	{ SV_ST_MUSTANG2_4_100, "AlphaStation 200 4/100 (\"Mustang II\")" },
	{ SV_ST_AVANTI_4_233, "AlphaStation 255/233" },
	{ 0, NULL },
};

void
dec_2100_a50_init(void)
{
	uint64_t variation;

	platform.family = "AlphaStation 200/400 (\"Avanti\")";

	if ((platform.model = alpha_dsr_sysname()) == NULL) {
		variation = hwrpb->rpb_variation & SV_ST_MASK;
		if (variation == SV_ST_AVANTI_XXX) {
			/* XXX apparently the same? */
			variation = SV_ST_AVANTI;
		}
		if ((platform.model = alpha_variation_name(variation,
		    dec_2100_a50_variations)) == NULL)
			platform.model = alpha_unknown_sysname();
	}

	platform.iobus = "apecs";
	platform.cons_init = dec_2100_a50_cons_init;
	platform.device_register = dec_2100_a50_device_register;
	platform.mcheck_handler = dec_2100_a50_mcheck_handler;

}

static void
dec_2100_a50_cons_init(void)
{
	struct apecs_config *acp;
	extern struct apecs_config apecs_configuration;

	acp = &apecs_configuration;
	apecs_init(acp);

	pci_consinit(&acp->ac_pc, &acp->ac_iot, &acp->ac_memt,
	    &acp->ac_iot, &acp->ac_memt);
}

static void
dec_2100_a50_device_register(device_t dev, void *aux)
{
	pci_find_bootdev(NULL, dev, aux);
}

static void
dec_2100_a50_mcheck(unsigned long mces, unsigned long type, unsigned long logout, struct trapframe *framep)
{
	struct mchkinfo *mcp;
	static const char *fmt1 = "        %-25s = 0x%016lx\n";
	int i, sysaddr;	
	mc_hdr_avanti *hdr;
	mc_uc_avanti *ptr;

	/*
	 * If we expected a machine check, just go handle it in common code.
	 */
	mcp  = &curcpu()->ci_mcinfo;
	if (mcp->mc_expected) {
		machine_check(mces, framep, type, logout);
		return;
	}

	hdr = (mc_hdr_avanti *) logout;
	ptr = (mc_uc_avanti *) (logout + sizeof (*hdr));

	printf("      Processor Machine Check (%lx), Code 0x%lx\n",
		   type, hdr->mcheck_code);
	printf("CPU state:\n");
	/* Print PAL fields */
	for (i = 0; i < 32; i += 2) {
		printf("\tPAL temp[%d-%d]\t\t= 0x%16lx 0x%16lx\n", i, i+1,
		    ptr->paltemp[i], ptr->paltemp[i+1]);
	}
	printf(fmt1, "Excepting Instruction Addr", ptr->exc_addr);
	printf(fmt1, "Summary of arithmetic traps", ptr->exc_sum);
	printf(fmt1, "Exception mask", ptr->exc_mask);
	printf(fmt1, "ICCSR", ptr->iccsr);
	printf(fmt1, "Base address for PALcode", ptr->pal_base);
	printf(fmt1, "HIER", ptr->hier);
	printf(fmt1, "HIRR", ptr->hirr);
	printf(fmt1, "MM_CSR", ptr->mm_csr);
	printf(fmt1, "DC_STAT", ptr->dc_stat);
	printf(fmt1, "DC_ADDR", ptr->dc_addr);
	printf(fmt1, "ABOX_CTL", ptr->abox_ctl);
	printf(fmt1, "Bus Interface Unit status", ptr->biu_stat);
	printf(fmt1, "Bus Interface Unit addr", ptr->biu_addr);
	printf(fmt1, "Bus Interface Unit control", ptr->biu_ctl);
	printf(fmt1, "Fill Syndrome", ptr->fill_syndrome);
	printf(fmt1, "Fill Address", ptr->fill_addr);
	printf(fmt1, "Effective VA", ptr->va);
	printf(fmt1, "BC_TAG", ptr->bc_tag);

	printf("\nCache and Memory Controller (21071-CA) state:\n");
	printf(fmt1, "COMA_GCR", ptr->coma_gcr);
	printf(fmt1, "COMA_EDSR", ptr->coma_edsr);
	printf(fmt1, "COMA_TER", ptr->coma_ter);
	printf(fmt1, "COMA_ELAR", ptr->coma_elar);
	printf(fmt1, "COMA_EHAR", ptr->coma_ehar);
	printf(fmt1, "COMA_LDLR", ptr->coma_ldlr);
	printf(fmt1, "COMA_LDHR", ptr->coma_ldhr);
	printf(fmt1, "COMA_BASE0", ptr->coma_base0);
	printf(fmt1, "COMA_BASE1", ptr->coma_base1);
	printf(fmt1, "COMA_BASE2", ptr->coma_base2);
	printf(fmt1, "COMA_CNFG0", ptr->coma_cnfg0);
	printf(fmt1, "COMA_CNFG1", ptr->coma_cnfg1);
	printf(fmt1, "COMA_CNFG2", ptr->coma_cnfg2);

	printf("\nPCI bridge (21071-DA) state:\n");

	printf(fmt1, "EPIC Diag. control/status", ptr->epic_dcsr);
	printf(fmt1, "EPIC_PEAR", ptr->epic_pear);
	printf(fmt1, "EPIC_SEAR", ptr->epic_sear);
	printf(fmt1, "EPIC_TBR1", ptr->epic_tbr1);
	printf(fmt1, "EPIC_TBR2", ptr->epic_tbr2);
	printf(fmt1, "EPIC_PBR1", ptr->epic_pbr1);
	printf(fmt1, "EPIC_PBR2", ptr->epic_pbr2);
	printf(fmt1, "EPIC_PMR1", ptr->epic_pmr1);
	printf(fmt1, "EPIC_PMR2", ptr->epic_pmr2);
	printf(fmt1, "EPIC_HARX1", ptr->epic_harx1);
	printf(fmt1, "EPIC_HARX2", ptr->epic_harx2);
	printf(fmt1, "EPIC_PMLT", ptr->epic_pmlt);
	printf(fmt1, "EPIC_TAG0", ptr->epic_tag0);
	printf(fmt1, "EPIC_TAG1", ptr->epic_tag1);
	printf(fmt1, "EPIC_TAG2", ptr->epic_tag2);
	printf(fmt1, "EPIC_TAG3", ptr->epic_tag3);
	printf(fmt1, "EPIC_TAG4", ptr->epic_tag4);
	printf(fmt1, "EPIC_TAG5", ptr->epic_tag5);
	printf(fmt1, "EPIC_TAG6", ptr->epic_tag6);
	printf(fmt1, "EPIC_TAG7", ptr->epic_tag7);
	printf(fmt1, "EPIC_DATA0", ptr->epic_data0);
	printf(fmt1, "EPIC_DATA1", ptr->epic_data1);
	printf(fmt1, "EPIC_DATA2", ptr->epic_data2);
	printf(fmt1, "EPIC_DATA3", ptr->epic_data3);
	printf(fmt1, "EPIC_DATA4", ptr->epic_data4);
	printf(fmt1, "EPIC_DATA5", ptr->epic_data5);
	printf(fmt1, "EPIC_DATA6", ptr->epic_data6);
	printf(fmt1, "EPIC_DATA7", ptr->epic_data7);

	printf("\n");

	if (type == ALPHA_SYS_MCHECK) {
	  printf("\nPCI bridge fault\n");
	  switch(hdr->mcheck_code) {
	  case AVANTI_RETRY_TIMEOUT:
	    printf("\tRetry timeout error accessing 0x%08lx.\n",
		   ptr->epic_pear & 0xffffffff);
	    break;

	  case AVANTI_DMA_DATA_PARITY:
	    printf("\tDMA data parity error accessing 0x%08lx.\n",
		   ptr->epic_pear & 0xffffffff);
	    break;

	  case AVANTI_IO_PARITY:
	    printf("\tI/O parity error at 0x%08lx during PCI cycle 0x%0lx.\n",
		   ptr->epic_pear & 0xffffffff,
		   (ptr->epic_dcsr >> 18) & 0xf);
	    break;

	  case AVANTI_TARGET_ABORT:
	    printf("\tPCI target abort at 0x%08lx during PCI cycle 0x%0lx.\n",
		   ptr->epic_pear & 0xffffffff,
		   (ptr->epic_dcsr >> 18) & 0xf);
	    break;

	  case AVANTI_NO_DEVICE:
	    printf("\tNo device responded at 0x%08lx during PCI cycle 0x%0lx\n.",
		   ptr->epic_pear & 0xffffffff,
		   (ptr->epic_dcsr >> 18) & 0xf);
	    break;

	  case AVANTI_CORRRECTABLE_MEMORY:
	    printf("\tCorrectable memory error reported.\n"
		   "\tWARNING ECC not implemented on this system!\n"
		   "\tError is incorrect.\n");
	    break;

	  case AVANTI_UNCORRECTABLE_PCI_MEMORY:
	    printf("\tUncorrectable memory error at %016lx reported "
		   "during DMA read.\n",
		   (ptr->epic_sear & 0xfffffff0) << 2);
	    break;

	  case AVANTI_INVALID_PT_LOOKUP:
	    printf("\tInvalid page table lookup during scatter/gather.\n" );
	    if (ptr->epic_dcsr & 0xf20)
	      printf("\tAddress lost.\n");
	    else
	      printf("\tBus address to 0x%08lx, PCI cycle 0x%0lx\n",
		     ptr->epic_pear & 0xffffffff,
		     (ptr->epic_dcsr >> 18) & 0xf);
	    break;

	  case AVANTI_MEMORY:
	    printf("\tMemory error at %016lx, ",
		   (ptr->epic_sear & 0xfffffff0) << 2);
	    sysaddr = (ptr->epic_sear & 0xffffffff) >> 21;
	    if (sysaddr >= ((ptr->coma_base0 >> 5) & 0x7ff) &&
		sysaddr < (((ptr->coma_base0 >> 5) & 0x7ff) +
			   (1 << (7 - (ptr->coma_cnfg0 >> 1)))))
	      printf("SIMM bank 0\n");
	    else if (sysaddr >= ((ptr->coma_base1 >> 5) & 0x7ff) &&
		     sysaddr < (((ptr->coma_base1 >> 5) & 0x7ff) +
				(1 << (7 - (ptr->coma_cnfg1 >> 1)))))
	      printf("SIMM bank 1\n");
	    else if (sysaddr >= ((ptr->coma_base2 >> 5) & 0x7ff) &&
		     sysaddr < (((ptr->coma_base2 >> 5) & 0x7ff) +
				(1 << (7 - (ptr->coma_cnfg2 >> 1)))))
	      printf("SIMM bank 2\n");
	    else
	      printf("invalid memory bank?\n");
	    break;

	  case AVANTI_BCACHE_TAG_ADDR_PARITY:
	    printf("\tBcache tag address parity error, caused by ");
	    if (ptr->coma_edsr & 0x20)
	      printf("victim write\n");
	    else if (ptr->coma_edsr & 0x10)
	      printf("DMA. ioCmd<2:0> = %0lx\n", (ptr->coma_edsr >> 6) & 7);
	    else
	      printf("CPU. cpuCReq<2:0> = %0lx\n", (ptr->coma_edsr >> 6) & 7);
	    break;

	  case AVANTI_BCACHE_TAG_CTRL_PARITY:
	    printf("\tBcache tag control parity error, caused by ");
	    if (ptr->coma_edsr & 0x20)
	      printf("victim write\n");
	    else if (ptr->coma_edsr & 0x10)
	      printf("DMA. ioCmd<2:0> = %0lx\n", (ptr->coma_edsr >> 6) & 7);
	    else
	      printf("CPU. cpuCReq<2:0> = %0lx\n", (ptr->coma_edsr >> 6) & 7);
	    break;
	
	  case AVANTI_NONEXISTENT_MEMORY:
	    printf("\tNonexistent memory error, caused by ");
	    if (ptr->coma_edsr & 0x20)
	      printf("victim write\n");
	    else if (ptr->coma_edsr & 0x10)
	      printf("DMA. ioCmd<2:0> = %0lx\n", (ptr->coma_edsr >> 6) & 7);
	    else
	      printf("CPU. cpuCReq<2:0> = %0lx\n", (ptr->coma_edsr >> 6) & 7);
	    break;

	  case AVANTI_IO_BUS:
	    printf("\tI/O bus error at %08lx during PCI cycle %0lx\n",
		   ptr->epic_pear & 0xffffffff, (ptr->epic_dcsr >> 18) & 0xf);
	    break;

	  case AVANTI_BCACHE_TAG_PARITY:
	    printf("\tBcache tag address parity error.\n"
		   "\tcReg_h cycle %0lx, address<7:0> 0x%02lx\n",
		   (ptr->biu_stat >> 4) & 7,
		   ptr->biu_addr & 0xff);
	    break;

	  case AVANTI_BCACHE_TAG_CTRL_PARITY2:
	    printf("\tBcache tag control parity error.\n"
		   "\tcReg_h cycle %0lx, address<7:0> 0x%02lx\n",
		   (ptr->biu_stat >> 4) & 7,
		   ptr->biu_addr & 0xff);
	    break;

	  }
	} else { /* ALPHA_PROC_MCHECK */
	  printf("\nProcessor fault\n");
	  switch(hdr->mcheck_code) {
	  case AVANTI_HARD_ERROR:
	    printf("\tHard error cycle.\n");
	    break;

	  case AVANTI_CORRECTABLE_ECC:
	    printf("\tCorrectable ECC error.\n"
		   "\tWARNING ECC not implemented on this system!\n"
		   "\tError is incorrect.\n");
	    break;

	  case AVANTI_NONCORRECTABLE_ECC:
	    printf("\tNoncorrectable ECC error.\n"
		   "\tWARNING ECC not implemented on this system!\n"
		   "\tError is incorrect.\n");
	    break;

	  case AVANTI_UNKNOWN_ERROR:
	    printf("\tUnknown error.\n");
	    break;

	  case AVANTI_SOFT_ERROR:
	    printf("\tSoft error cycle.\n");
	    break;

	  case AVANTI_BUGCHECK:
	    printf("\tBugcheck.\n");
	    break;

	  case AVANTI_OS_BUGCHECK:
	    printf("\tOS Bugcheck.\n");
	    break;

	  case AVANTI_DCACHE_FILL_PARITY:
	    printf("\tPrimary Dcache data fill parity error.\n"
		   "\tDcache Quadword %lx, address %08lx\n",
		   (ptr->biu_stat >> 12) & 0x3,
		   (ptr->fill_addr >> 8) & 0x7f);
	    break;

	  case AVANTI_ICACHE_FILL_PARITY:
	    printf("\tPrimary Icache data fill parity error.\n"
		   "\tDcache Quadword %lx, address %08lx\n",
		   (ptr->biu_stat >> 12) & 0x3,
		   (ptr->fill_addr >> 8) & 0x7f);
	    break;
	  }
	}
	
	/*
	 * Now that we've printed all sorts of useful information
	 * and have decided that we really can't do any more to
	 * respond to the error, go on to the common code for
	 * final disposition. Usually this means that we die.
	 */
	/*
	 * XXX: HANDLE PCI ERRORS HERE?
	 */
	machine_check(mces, framep, type, logout);
}

static void
dec_2100_a50_mcheck_handler(unsigned long mces, struct trapframe *framep, unsigned long vector, unsigned long param)
{
	switch (vector) {
	case ALPHA_SYS_MCHECK:
	case ALPHA_PROC_MCHECK:
		dec_2100_a50_mcheck(mces, vector, param, framep);
		break;
	default:
		printf("2100_A50_MCHECK: unknown check vector 0x%lx\n", vector);
		machine_check(mces, framep, vector, param);
		break;
	}
}
