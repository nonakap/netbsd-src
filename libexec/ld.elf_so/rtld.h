/*	$NetBSD: rtld.h,v 1.150 2025/05/02 23:04:31 riastradh Exp $	 */

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

#ifndef RTLD_H
#define RTLD_H

#include <dlfcn.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/exec_elf.h>
#include <sys/tls.h>
#include "rtldenv.h"
#include "link.h"

#if defined(_RTLD_SOURCE)

#if defined(__ARM_EABI__) && !defined(__ARM_DWARF_EH__)
#include "unwind.h"
#endif

#ifndef	RTLD_DEFAULT_LIBRARY_PATH
#define	RTLD_DEFAULT_LIBRARY_PATH	"/usr/lib"
#endif
#define _PATH_LD_HINTS			"/etc/ld.so.conf"

extern size_t _rtld_pagesz;

#define round_down(x)	((x) & ~(_rtld_pagesz - 1))
#define round_up(x)	round_down((x) + _rtld_pagesz - 1)

#define NEW(type)	((type *) xmalloc(sizeof(type)))
#define CNEW(type)	((type *) xcalloc(sizeof(type)))

/*
 * Fill in a DoneList with an allocation large enough to hold all of
 * the currently-loaded objects. Keep this in a macro since it calls
 * alloca and we want that to occur within the scope of the caller.
 * Callers must be built with -Wno-stack-protector.
 */
#define _rtld_donelist_init(dlp)					\
    ((dlp)->num_alloc = _rtld_objcount,					\
    (dlp)->objs = alloca((dlp)->num_alloc * sizeof((dlp)->objs[0])),	\
    assert((dlp)->objs != NULL),					\
    (dlp)->num_used = 0)


typedef struct Struct_Elf_Hash {
	unsigned long sysv;
	unsigned long gnu;
} Elf_Hash;
#endif /* _RTLD_SOURCE */

/*
 * C++ has mandated the use of the following keywords for its new boolean
 * type.  We might as well follow their lead.
 */
struct Struct_Obj_Entry;

typedef struct Struct_Objlist_Entry {
	SIMPLEQ_ENTRY(Struct_Objlist_Entry) link;
	struct Struct_Obj_Entry *obj;
} Objlist_Entry;

typedef SIMPLEQ_HEAD(Struct_Objlist, Struct_Objlist_Entry) Objlist;

typedef struct Struct_Name_Entry {
	SIMPLEQ_ENTRY(Struct_Name_Entry) link;
	char	name[1];
} Name_Entry;

typedef struct Struct_Needed_Entry {
	struct Struct_Needed_Entry *next;
	struct Struct_Obj_Entry *obj;
	unsigned long   name;	/* Offset of name in string table */
} Needed_Entry;

typedef struct _rtld_search_path_t {
	struct _rtld_search_path_t *sp_next;
	const char     *sp_path;
	size_t          sp_pathlen;
} Search_Path;

typedef struct Struct_Ver_Entry {
	Elf_Word        hash;
	u_int           flags;
	const char     *name;
	const char     *file;
} Ver_Entry;

/* Ver_Entry.flags */
#define VER_INFO_HIDDEN	0x01

#define RTLD_MAX_ENTRY 10
#define RTLD_MAX_LIBRARY 4
#define RTLD_MAX_CTL 2
typedef struct _rtld_library_xform_t {
	struct _rtld_library_xform_t *next;
	char *name;
	const char *ctlname;
	struct {
		char *value;
		char *library[RTLD_MAX_LIBRARY];
	} entry[RTLD_MAX_ENTRY];
} Library_Xform;

/*
 * Shared object descriptor.
 *
 * Items marked with "(%)" are dynamically allocated, and must be freed
 * when the structure is destroyed.
 */

typedef void (*fptr_t)(void);

typedef struct Struct_Obj_Entry {
	struct Struct_Obj_Entry *next;
	char           *path;		/* Pathname of underlying file (%) */
	int             refcount;
	int             dl_refcount;	/* Number of times loaded by dlopen */

	/* These items are computed by map_object() or by digest_phdr(). */
	caddr_t         mapbase;	/* Base address of mapped region */
	size_t          mapsize;	/* Size of mapped region in bytes */
	size_t          textsize;	/* Size of text segment in bytes */
	Elf_Addr        vaddrbase;	/* Base address in shared object file */
	caddr_t         relocbase;	/* Reloc const = mapbase - *vaddrbase */
	Elf_Dyn        *dynamic;	/* Dynamic section */
	caddr_t         entry;		/* Entry point */
	const Elf_Phdr *phdr;		/* Program header (may be xmalloc'ed) */
	size_t		phsize;		/* Size of program header in bytes */

	/* Items from the dynamic section. */
	Elf_Addr       *pltgot;		/* PLTGOT table */
	const Elf_Rel  *rel;		/* Relocation entries */
	const Elf_Rel  *rellim;		/* Limit of Relocation entries */
	const Elf_Rela *rela;		/* Relocation entries */
	const Elf_Rela *relalim;	/* Limit of Relocation entries */
	const Elf_Relr *relr;		/* Relative relocations */
	const Elf_Relr *relrlim;	/* Limit of relative relocations */
	const Elf_Rel  *pltrel;		/* PLT relocation entries */
	const Elf_Rel  *pltrellim;	/* Limit of PLT relocation entries */
	const Elf_Rela *pltrela;	/* PLT relocation entries */
	const Elf_Rela *pltrelalim;	/* Limit of PLT relocation entries */
	const Elf_Sym  *symtab;		/* Symbol table */
	const char     *strtab;		/* String table */
	unsigned long   strsize;	/* Size in bytes of string table */
#if defined(__mips__) || defined(__riscv__)
	Elf_Word        local_gotno;	/* Number of local GOT entries */
	Elf_Word        symtabno;	/* Number of dynamic symbols */
	Elf_Word        gotsym;		/* First dynamic symbol in GOT */
#endif

	/* SysV Hash fields */
	const Elf_Symindx *buckets;	/* Hash table buckets array */
	unsigned long	unused1;	/* Used to be nbuckets */
	const Elf_Symindx *chains;	/* Hash table chain array */
	unsigned long   nchains;	/* Number of chains */

	Search_Path    *rpaths;		/* Search path specified in object */
	Needed_Entry   *needed;		/* Shared objects needed by this (%) */

	fptr_t		init;		/* Initialization function to call */
	fptr_t		fini;		/* Termination function to call */

	u_int32_t	mainprog:1,	/* True if this is the main program */
	        	rtld:1,		/* True if this is the dynamic linker */
			textrel:1,	/* True if there are relocations to
					 * text seg */
			symbolic:1,	/* True if generated with
					 * "-Bsymbolic" */
			printed:1,	/* True if ldd has printed it */
			isdynamic:1,	/* True if this is a pure PIC object */
			mainref:1,	/* True if on _rtld_list_main */
			globalref:1,	/* True if on _rtld_list_global */
			init_done:1,	/* True if .init has been added */
			init_called:1,	/* True if .init function has been
					 * called */
			fini_called:1,	/* True if .fini function has been
					 * called */
			z_now:1,	/* True if object's symbols should be
					   bound immediately */
			z_nodelete:1,	/* True if object should never be
					   unloaded */
			z_initfirst:1,	/* True if object's .init/.fini take
					 * priority over others */
			z_noopen:1,	/* True if object should never be
					   dlopen'ed */
			phdr_loaded:1,	/* Phdr is loaded and doesn't need to
					 * be freed. */
#ifdef __alpha__
			secureplt:1,	/* True if PLT is read-only format */
#endif
#if defined(__HAVE_TLS_VARIANT_I) || defined(__HAVE_TLS_VARIANT_II)
			tls_static:1,	/* True if static TLS offset
					 * has been allocated */
			tls_dynamic:1,	/* True if any non-static DTV entry
					 * has been allocated */
#endif
			ref_nodel:1,	/* Refcount increased to prevent dlclose */
			sysv_hash:1,	/* SysV Hash available */
			gnu_hash:1;	/* GNU Hash available */

	struct link_map linkmap;	/* for the debugger */

	/* These items are computed by map_object() or by digest_phdr(). */
	const char     *interp;	/* Pathname of the interpreter, if any */
	Objlist         dldags;	/* Object belongs to these dlopened DAGs (%) */
	Objlist         dagmembers;	/* DAG has these members (%) */
	dev_t           dev;		/* Object's filesystem's device */
	ino_t           ino;		/* Object's inode number */

	void		*ehdr;

	/* SysV Hash fields */
	uint32_t        nbuckets;	/* Number of buckets */
	uint32_t        nbuckets_m;	/* Precomputed for fast remainder */
	uint8_t         nbuckets_s1;
	uint8_t         nbuckets_s2;

	/* GNU Hash fields */
	const uint32_t *buckets_gnu;	/* Hash table buckets array */
	uint32_t	nbuckets_gnu;	/* Number of GNU hash buckets */
	uint32_t	nbuckets_m_gnu;	/* Precomputed for fast remainder */
	uint8_t		nbuckets_s1_gnu;
	uint8_t		nbuckets_s2_gnu;
	const uint32_t *chains_gnu;	/* Hash table chain array */
#define nchains_gnu	nchains		/* Number of symbols, shared with SysV Hash */
	const Elf_Addr *bloom_gnu;
	uint32_t	symndx_gnu;	/* First accessible symbol on dynsym table */
	uint32_t	mask_bm_gnu;	/* Bloom filter words - 1 (bitmask) */
	uint32_t	shift2_gnu;	/* Bloom filter shift count */

	size_t		pathlen;	/* Pathname length */
	SIMPLEQ_HEAD(, Struct_Name_Entry) names; /* List of names for this
						  * object we know about. */

#ifdef __powerpc__
#ifdef _LP64
	Elf_Addr	glink;		/* global linkage */
#else
	Elf_Addr       *gotptr;		/* GOT table (secure-plt only) */
#endif
#endif

#if defined(__HAVE_TLS_VARIANT_I) || defined(__HAVE_TLS_VARIANT_II)
	/* Thread Local Storage support for this module */
	size_t		tlsindex;	/* Index in DTV */
	void		*tlsinit;	/* Base address of TLS init block */
	size_t		tlsinitsize;	/* Size of TLS init block */
	size_t		tlssize;	/* Size of TLS block */
	size_t		tlsoffset;	/* Offset in the static TLS block */
	size_t		tlsalign;	/* Needed alignment for static TLS */
#endif

#ifdef GNU_RELRO
	/* relocation readonly */
	void		*relro_page;
	size_t		relro_size;
#endif

	/* symbol versioning */
	const Elf_Verneed *verneed;	/* Required versions. */
	Elf_Word	verneednum;	/* Number of entries in verneed table */
	const Elf_Verdef  *verdef;	/* Provided versions. */
	Elf_Word	verdefnum;	/* Number of entries in verdef table */
	const Elf_Versym *versyms;	/* Symbol versions table */

	Ver_Entry	*vertab;	/* Versions required/defined by this
					 * object */
	int		vertabnum;	/* Number of entries in vertab */

	/* init_array/fini_array */
	fptr_t		*init_array;	/* start of init array */
	size_t		init_arraysz;	/* # of entries in it */
	fptr_t		*fini_array;	/* start of fini array */
	size_t		fini_arraysz;	/* # of entries in it */
	/* IRELATIVE relocations */
	size_t		ifunc_remaining;
#if \
    defined(__aarch64__) || \
    defined(__arm__) || \
    defined(__i386__) || \
    defined(__powerpc__) || \
    defined(__sparc__) || \
    defined(__x86_64__)
#define IFUNC_NONPLT
	/* On SPARC, the PLT variant is called JMP_IREL and counted above. */
	size_t		ifunc_remaining_nonplt;
#endif
	size_t		cxa_refcount;	/* For TLS destructors. */
#ifdef __ARM_EABI__
	void		*exidx_start;
	size_t		exidx_sz;
#endif
} Obj_Entry;

typedef struct Struct_DoneList {
	const Obj_Entry **objs;		/* Array of object pointers */
	unsigned int num_alloc;		/* Allocated size of the array */
	unsigned int num_used;		/* Number of array slots used */
} DoneList;


#if defined(_RTLD_SOURCE)

extern struct r_debug _rtld_debug;
extern Search_Path *_rtld_default_paths;
extern Obj_Entry *_rtld_objlist;
extern Obj_Entry **_rtld_objtail;
extern u_int _rtld_objcount;
extern u_int _rtld_objloads;
extern const uintptr_t _rtld_compat_obj[];
extern Obj_Entry *_rtld_objmain;
extern Obj_Entry _rtld_objself;
extern Search_Path *_rtld_paths;
extern Library_Xform *_rtld_xforms;
extern bool _rtld_trust;
extern Objlist _rtld_list_global;
extern Objlist _rtld_list_main;
extern Elf_Sym _rtld_sym_zero;
extern u_int _rtld_objgen;

#define	RTLD_MODEMASK 0x3

/* Flags to be passed into _rtld_symlook_ family of functions. */
#define SYMLOOK_IN_PLT	0x01	/* Lookup for PLT symbol */
#define SYMLOOK_DLSYM	0x02	/* Return newest versioned symbol.
				   Used by dlsym. */

/* Flags for _rtld_load_object() and friends. */
#define	_RTLD_GLOBAL	0x01	/* Add object to global DAG. */
#define	_RTLD_MAIN	0x02
#define	_RTLD_NOLOAD	0x04	/* dlopen() specified RTLD_NOLOAD. */
#define	_RTLD_DLOPEN	0x08	/* Load_object() called from dlopen(). */

/* Preallocation for static TLS model */
#define	RTLD_STATIC_TLS_RESERVATION	64

/* rtld.c */
__dso_public char *dlerror(void);
__dso_public void *dlopen(const char *, int);
__dso_public void *dlsym(void *, const char *);
__dso_public int dlclose(void *);
__dso_public int dladdr(const void *, Dl_info *);
__dso_public int dlinfo(void *, int, void *);
__dso_public int dl_iterate_phdr(int (*)(struct dl_phdr_info *, size_t, void *),
    void *);

__dso_public void *_dlauxinfo(void) __pure;
__dso_public void __dl_cxa_refcount(void *addr, ssize_t delta);

__dso_public pid_t __locked_fork(int *);

#if defined(__ARM_EABI__) && !defined(__ARM_DWARF_EH__)
/*
 * This is used by libgcc to find the start and length of the exception table
 * associated with a PC.
 */
__dso_public _Unwind_Ptr __gnu_Unwind_Find_exidx(_Unwind_Ptr, int *);
#endif

/* These aren't exported */
void _rtld_error(const char *, ...) __printflike(1,2);
void _rtld_die(void) __dead;
void *_rtld_objmain_sym(const char *);
__dso_public void _rtld_debug_state(void) __noinline;
void _rtld_linkmap_add(Obj_Entry *);
void _rtld_linkmap_delete(Obj_Entry *);
void _rtld_objlist_push_head(Objlist *, Obj_Entry *);
void _rtld_objlist_push_tail(Objlist *, Obj_Entry *);
Objlist_Entry *_rtld_objlist_find(Objlist *, const Obj_Entry *);
void _rtld_ref_dag(Obj_Entry *);

void _rtld_shared_enter(void);
void _rtld_shared_exit(void);
void _rtld_exclusive_enter(sigset_t *);
void _rtld_exclusive_exit(sigset_t *);

int _rtld_relro(const Obj_Entry *, bool);

/* expand.c */
size_t _rtld_expand_path(char *, size_t, const char *, const char *,\
    const char *);

/* headers.c */
void _rtld_digest_dynamic(const char *, Obj_Entry *);
Obj_Entry *_rtld_digest_phdr(const Elf_Phdr *, int, caddr_t);

/* load.c */
Obj_Entry *_rtld_load_object(const char *, int);
int _rtld_load_needed_objects(Obj_Entry *, int);
int _rtld_preload(const char *);

#define	OBJ_ERR	(Obj_Entry *)(-1)
/* path.c */
void _rtld_add_paths(const char *, Search_Path **, const char *);
void _rtld_process_hints(const char *, Search_Path **, Library_Xform **,
    const char *);
int _rtld_sysctl(const char *, void *, size_t *);

/* reloc.c */
int _rtld_do_copy_relocations(const Obj_Entry *);
int _rtld_relocate_objects(Obj_Entry *, bool);
int _rtld_relocate_nonplt_objects(Obj_Entry *);
int _rtld_relocate_plt_lazy(Obj_Entry *);
int _rtld_relocate_plt_objects(const Obj_Entry *);
void _rtld_setup_pltgot(const Obj_Entry *);
Elf_Addr _rtld_resolve_ifunc(const Obj_Entry *, const Elf_Sym *);
Elf_Addr _rtld_resolve_ifunc2(const Obj_Entry *, Elf_Addr);

void _rtld_call_ifunc(Obj_Entry *, sigset_t *, u_int);

/* search.c */
Obj_Entry *_rtld_load_library(const char *, const Obj_Entry *, int);

/* symbol.c */
const Elf_Sym *_rtld_symlook_obj(const char *, Elf_Hash *,
    const Obj_Entry *, u_int, const Ver_Entry *);
const Elf_Sym *_rtld_find_symdef(unsigned long, const Obj_Entry *,
    const Obj_Entry **, u_int);
const Elf_Sym *_rtld_find_plt_symdef(unsigned long, const Obj_Entry *,
    const Obj_Entry **, bool);

const Elf_Sym *_rtld_symlook_list(const char *, Elf_Hash *,
    const Objlist *, const Obj_Entry **, u_int, const Ver_Entry *, DoneList *);
const Elf_Sym *_rtld_symlook_default(const char *, Elf_Hash *,
    const Obj_Entry *, const Obj_Entry **, u_int, const Ver_Entry *);
const Elf_Sym *_rtld_symlook_needed(const char *, Elf_Hash *,
    const Needed_Entry *, const Obj_Entry **, u_int, const Ver_Entry *,
    DoneList *, DoneList *);

/* symver.c */
void _rtld_object_add_name(Obj_Entry *, const char *);
int _rtld_object_match_name(const Obj_Entry *, const char *);
int _rtld_verify_object_versions(Obj_Entry *);

static __inline const Ver_Entry *
_rtld_fetch_ventry(const Obj_Entry *obj, unsigned long symnum)
{
	Elf_Half vernum;

	if (obj->vertab) {
		vernum = VER_NDX(obj->versyms[symnum].vs_vers);
		if (vernum >= obj->vertabnum) {
			_rtld_error("%s: symbol %s has wrong verneed value %d",
			    obj->path, &obj->strtab[symnum], vernum);
		} else if (obj->vertab[vernum].hash) {
			return &obj->vertab[vernum];
		}
	}
	return NULL;
}

#if defined(__HAVE_TLS_VARIANT_I) || defined(__HAVE_TLS_VARIANT_II)
/* tls.c */
void *_rtld_tls_get_addr(void *, size_t, size_t);
void _rtld_tls_initial_allocation(void);
int _rtld_tls_offset_allocate(Obj_Entry *);
void _rtld_tls_offset_free(Obj_Entry *);

extern size_t _rtld_tls_dtv_generation;
extern size_t _rtld_tls_max_index;

__dso_public extern void *__tls_get_addr(void *);
#ifdef __i386__
__dso_public extern void *___tls_get_addr(void *)
    __attribute__((__regparm__(1)));
#endif
#endif

/* map_object.c */
struct stat;
Obj_Entry *_rtld_map_object(const char *, int, const struct stat *);
void _rtld_obj_free(Obj_Entry *);
Obj_Entry *_rtld_obj_new(void);

#ifdef RTLD_LOADER
/* function descriptors */
#ifdef __HAVE_FUNCTION_DESCRIPTORS
Elf_Addr _rtld_function_descriptor_alloc(const Obj_Entry *,
    const Elf_Sym *, Elf_Addr);
const void *_rtld_function_descriptor_function(const void *);

Elf_Addr _rtld_call_function_addr(const Obj_Entry *, Elf_Addr);
#else
static inline Elf_Addr
_rtld_call_function_addr(const Obj_Entry *obj, Elf_Addr addr)
{
	return ((Elf_Addr(*)(void))addr)();
}
#endif /* __HAVE_FUNCTION_DESCRIPTORS */
#endif /* RTLD_LOADER */

#endif /* _RTLD_SOURCE */

#endif /* RTLD_H */
