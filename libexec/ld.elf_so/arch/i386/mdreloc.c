/*	$NetBSD: mdreloc.c,v 1.48 2025/04/16 17:37:48 riastradh Exp $	*/

/*
 * Copyright 1996 John D. Polstra.
 * Copyright 1996 Matt Thomas <matt@3am-software.com>
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by John Polstra.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * i386 ELF relocations.
 *
 * References:
 *
 *	[ABI386-4] System V Application Binary Interface: Intel386
 *	Architecture Processor Supplement, Fourth Edition, 1997-03-19,
 *	The Santa Cruz Operation, Inc.
 *	https://www.sco.com/developers/devspecs/abi386-4.pdf
 *	https://web.archive.org/web/20250329184450/https://www.sco.com/developers/devspecs/abi386-4.pdf
 *
 * Note: Intel and SuSE have published an update to the i386 ELF
 * supplement, but it is not entirely compatible (e.g., it requires
 * 16-byte alignment for the stack pointer, not just 4-byte alignment),
 * so it is not reliable as a normative reference:
 *
 *	[ABI386-2015] System V Application Binary Interface: Intel386
 *	Architecture Processor Supplement, Version 1.0, 2015-02-03.
 *	https://uclibc.org/docs/psABI-i386.pdf
 *	https://web.archive.org/web/20250118211449/https://uclibc.org/docs/psABI-i386.pdf
 *	https://gitlab.com/x86-psABIs/i386-ABI
 */

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD: mdreloc.c,v 1.48 2025/04/16 17:37:48 riastradh Exp $");
#endif /* not lint */

#include <sys/types.h>
#include <machine/lwp_private.h>

#include "debug.h"
#include "rtld.h"

void _rtld_bind_start(void);
void _rtld_relocate_nonplt_self(Elf_Dyn *, Elf_Addr);
caddr_t _rtld_bind(const Obj_Entry *, Elf_Word);

#define rdbg_symname(obj, rela) \
	((obj)->strtab + (obj)->symtab[ELF_R_SYM((rela)->r_info)].st_name)

void
_rtld_setup_pltgot(const Obj_Entry *obj)
{
	obj->pltgot[1] = (Elf_Addr) obj;
	obj->pltgot[2] = (Elf_Addr) &_rtld_bind_start;
}

void
_rtld_relocate_nonplt_self(Elf_Dyn *dynp, Elf_Addr relocbase)
{
	const Elf_Rel *rel = 0, *rellim;
	Elf_Addr relsz = 0;
	Elf_Addr *where;

	for (; dynp->d_tag != DT_NULL; dynp++) {
		switch (dynp->d_tag) {
		case DT_REL:
			rel = (const Elf_Rel *)(relocbase + dynp->d_un.d_ptr);
			break;
		case DT_RELSZ:
			relsz = dynp->d_un.d_val;
			break;
		}
	}
	if (rel == 0 || relsz == 0)
		return;
	rellim = (const Elf_Rel *)((const uint8_t *)rel + relsz);
	for (; rel < rellim; rel++) {
		where = (Elf_Addr *)(relocbase + rel->r_offset);
		*where += (Elf_Addr)relocbase;
	}
}

int
_rtld_relocate_nonplt_objects(Obj_Entry *obj)
{
	const Elf_Rel *rel;
	Elf_Addr target = 0;
	const Elf_Sym   *def = NULL;
	const Obj_Entry *defobj = NULL;
	unsigned long last_symnum = ULONG_MAX;

	for (rel = obj->rel; rel < obj->rellim; rel++) {
		Elf_Addr        *where;
		Elf_Addr         tmp;
		unsigned long	 symnum;

		where = (Elf_Addr *)(obj->relocbase + rel->r_offset);

		switch (ELF_R_TYPE(rel->r_info)) {
		case R_TYPE(PC32):
		case R_TYPE(GOT32):
		case R_TYPE(32):
		case R_TYPE(GLOB_DAT):
		case R_TYPE(TLS_TPOFF):
		case R_TYPE(TLS_TPOFF32):
		case R_TYPE(TLS_DTPMOD32):
		case R_TYPE(TLS_DTPOFF32):
			symnum = ELF_R_SYM(rel->r_info);
			if (symnum != last_symnum) {
				last_symnum = symnum;
				def = _rtld_find_symdef(symnum, obj, &defobj,
				    false);
				if (def == NULL)
					return -1;
			}
			break;
		default:
			break;
		}


		switch (ELF_R_TYPE(rel->r_info)) {
		case R_TYPE(NONE):
			break;

#if 1 /* XXX should not occur */
		case R_TYPE(PC32):
			target = (Elf_Addr)(defobj->relocbase + def->st_value);

			*where += target - (Elf_Addr)where;
			rdbg(("PC32 %s in %s --> %p in %s",
			    rdbg_symname(obj, rel),
			    obj->path, (void *)*where, defobj->path));
			break;

		case R_TYPE(GOT32):
#endif
		case R_TYPE(32):
		case R_TYPE(GLOB_DAT):
			target = (Elf_Addr)(defobj->relocbase + def->st_value);

			tmp = target + *where;
			if (*where != tmp)
				*where = tmp;
			rdbg(("32/GLOB_DAT %s in %s --> %p in %s",
			    rdbg_symname(obj, rel),
			    obj->path, (void *)*where, defobj->path));
			break;


		case R_TYPE(IRELATIVE):
			/* IFUNC relocations are handled in _rtld_call_ifunc */
			if (obj->ifunc_remaining_nonplt == 0) {
				obj->ifunc_remaining_nonplt =
				    obj->rellim - rel;
			}
			/* FALL-THROUGH */

		case R_TYPE(RELATIVE):
			*where += (Elf_Addr)obj->relocbase;
			rdbg(("RELATIVE in %s --> %p", obj->path,
			    (void *)*where));
			break;

		case R_TYPE(COPY):
			/*
			 * These are deferred until all other relocations have
			 * been done.  All we do here is make sure that the
			 * COPY relocation is not in a shared library.  They
			 * are allowed only in executable files.
			 */
			if (obj->isdynamic) {
				_rtld_error(
			"%s: Unexpected R_COPY relocation in shared library",
				    obj->path);
				return -1;
			}
			rdbg(("COPY (avoid in main)"));
			break;

		case R_TYPE(TLS_TPOFF):
			if (!defobj->tls_static &&
			    _rtld_tls_offset_allocate(__UNCONST(defobj)))
				return -1;

			*where += (Elf_Addr)(def->st_value - defobj->tlsoffset);

			rdbg(("TLS_TPOFF %s in %s --> %p",
			    rdbg_symname(obj, rel),
			    obj->path, (void *)*where));
			break;

		case R_TYPE(TLS_TPOFF32):
			if (!defobj->tls_static &&
			    _rtld_tls_offset_allocate(__UNCONST(defobj)))
				return -1;

			*where += (Elf_Addr)(defobj->tlsoffset - def->st_value);
			rdbg(("TLS_TPOFF32 %s in %s --> %p",
			    rdbg_symname(obj, rel),
			    obj->path, (void *)*where));
			break;

		case R_TYPE(TLS_DTPMOD32):
			*where = (Elf_Addr)(defobj->tlsindex);

			rdbg(("TLS_DTPMOD32 %s in %s --> %p",
			    rdbg_symname(obj, rel),
			    obj->path, (void *)*where));
			break;

		case R_TYPE(TLS_DTPOFF32):
			*where = (Elf_Addr)(def->st_value);

			rdbg(("TLS_DTPOFF32 %s in %s --> %p",
			    rdbg_symname(obj, rel),
			    obj->path, (void *)*where));

			break;

		default:
			rdbg(("sym = %lu, type = %lu, offset = %p, "
			    "contents = %p, symbol = %s",
			    (u_long)ELF_R_SYM(rel->r_info),
			    (u_long)ELF_R_TYPE(rel->r_info),
			    (void *)rel->r_offset, (void *)*where,
			    rdbg_symname(obj, rel)));
			_rtld_error("%s: Unsupported relocation type %ld "
			    "in non-PLT relocations",
			    obj->path, (u_long) ELF_R_TYPE(rel->r_info));
			return -1;
		}
	}
	return 0;
}

int
_rtld_relocate_plt_lazy(Obj_Entry *obj)
{
	const Elf_Rel *rel;

	for (rel = obj->pltrellim; rel-- > obj->pltrel; ) {
		Elf_Addr *where = (Elf_Addr *)(obj->relocbase + rel->r_offset);

		assert(ELF_R_TYPE(rel->r_info) == R_TYPE(JMP_SLOT) ||
		       ELF_R_TYPE(rel->r_info) == R_TYPE(IRELATIVE));

		if (ELF_R_TYPE(rel->r_info) == R_TYPE(IRELATIVE))
			obj->ifunc_remaining = obj->pltrellim - rel;

		/* Just relocate the GOT slots pointing into the PLT */
		*where += (Elf_Addr)obj->relocbase;
		rdbg(("fixup !main in %s --> %p", obj->path, (void *)*where));
	}

	return 0;
}

static inline int
_rtld_relocate_plt_object(const Obj_Entry *obj, const Elf_Rel *rel,
	Elf_Addr *tp)
{
	Elf_Addr *where = (Elf_Addr *)(obj->relocbase + rel->r_offset);
	Elf_Addr target;
	const Elf_Sym *def;
	const Obj_Entry *defobj;
	unsigned long info = rel->r_info;

	if (ELF_R_TYPE(info) == R_TYPE(IRELATIVE))
		return 0;

	assert(ELF_R_TYPE(info) == R_TYPE(JMP_SLOT));

	def = _rtld_find_plt_symdef(ELF_R_SYM(info), obj, &defobj, tp != NULL);
	if (__predict_false(def == NULL))
		return -1;
	if (__predict_false(def == &_rtld_sym_zero))
		return 0;

	if (ELF_ST_TYPE(def->st_info) == STT_GNU_IFUNC) {
		if (tp == NULL)
			return 0;
		target = _rtld_resolve_ifunc(defobj, def);
	} else {
		target = (Elf_Addr)(defobj->relocbase + def->st_value);
	}

	rdbg(("bind now/fixup in %s --> old=%p new=%p",
	    defobj->strtab + def->st_name, (void *)*where,
	    (void *)target));
	if (*where != target)
		*where = target;
	if (tp)
		*tp = target;
	return 0;
}

caddr_t
_rtld_bind(const Obj_Entry *obj, Elf_Word reloff)
{
	const Elf_Rel *rel = (const Elf_Rel *)((const uint8_t *)obj->pltrel
	    + reloff);
	Elf_Addr new_value;
	int err;

	new_value = 0;	/* XXX gcc */

	_rtld_shared_enter();
	err = _rtld_relocate_plt_object(obj, rel, &new_value);
	if (err)
		_rtld_die();
	_rtld_shared_exit();

	return (caddr_t)new_value;
}

int
_rtld_relocate_plt_objects(const Obj_Entry *obj)
{
	const Elf_Rel *rel;
	int err = 0;

	for (rel = obj->pltrel; rel < obj->pltrellim; rel++) {
		err = _rtld_relocate_plt_object(obj, rel, NULL);
		if (err)
			break;
	}
	return err;
}

/*
 * i386 specific GNU variant of __tls_get_addr using register based
 * argument passing.
 */
#define	DTV_MAX_INDEX(dtv)	((size_t)((dtv)[-1]))

__dso_public __attribute__((__regparm__(1))) void *
___tls_get_addr(void *arg_)
{
	size_t *arg = (size_t *)arg_;
	void **dtv;
	struct tls_tcb *tcb = __lwp_getprivate_fast();
	size_t idx = arg[0], offset = arg[1];

	dtv = tcb->tcb_dtv;

	if (__predict_true(idx < DTV_MAX_INDEX(dtv) && dtv[idx] != NULL))
		return (uint8_t *)dtv[idx] + offset;

	return _rtld_tls_get_addr(tcb, idx, offset);
}
