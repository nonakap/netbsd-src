/*	$NetBSD: rune.c,v 1.49 2025/04/04 21:52:19 riastradh Exp $	*/
/*-
 * Copyright (c)2010 Citrus Project,
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/endian.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#define __SETLOCALE_SOURCE__
#include <locale.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include "setlocale_local.h"

#include "citrus_module.h"
#include "citrus_ctype.h"

#include "runetype_local.h"

#include "multibyte.h"

#include "_wctype_local.h"
#include "_wctrans_local.h"

typedef struct {
	_RuneLocale rl;
#ifdef __CHAR_UNSIGNED__
	unsigned short	rlp_ctype_tab  [_CTYPE_NUM_CHARS + 1];
	short		rlp_tolower_tab[_CTYPE_NUM_CHARS + 1];
	short		rlp_toupper_tab[_CTYPE_NUM_CHARS + 1];
#else
	unsigned short	*rlp_ctype_tab;
	short		*rlp_tolower_tab;
	short		*rlp_toupper_tab;
#endif
	char		rlp_codeset[33]; /* XXX */

#ifdef __BUILD_LEGACY
	unsigned char	rlp_compat_bsdctype[_CTYPE_NUM_CHARS + 1];
#endif
} _RuneLocalePriv;

#ifndef __CHAR_UNSIGNED__

#define	roundup(X, N)	((((X) + ((N) - 1))/(N))*(N))

static void *
alloc_guarded(size_t elemsize, size_t nelem)
{
	const unsigned long page_size = sysconf(_SC_PAGESIZE);
	size_t nbytes = 0;
	void *p = MAP_FAILED, *q = NULL;

	_DIAGASSERT(elemsize != 0);
	if (nelem > SIZE_MAX/elemsize)
		goto fail;
	nbytes = page_size + roundup(elemsize*nelem, page_size);
	p = mmap(NULL, nbytes, PROT_READ|PROT_WRITE, MAP_ANON,
	    /*fd*/-1, /*offset*/0);
	if (p == MAP_FAILED)
		goto fail;
	if (mprotect(p, page_size, PROT_NONE) == -1)
		goto fail;
	q = (char *)p + page_size;
	return q;

fail:	if (p != MAP_FAILED)
		(void)munmap(p, nbytes);
	return NULL;
}

static void
free_guarded(void *q, size_t elemsize, size_t nelem)
{
	const unsigned long page_size = sysconf(_SC_PAGESIZE);
	size_t nbytes = 0;
	void *p;

	if (q == NULL)
		return;
	_DIAGASSERT(elemsize <= SIZE_MAX/nelem);
	nbytes = page_size + roundup(elemsize*nelem, page_size);
	p = (char *)q - page_size;
	(void)munmap(p, nbytes);
}

#endif	/* !__CHAR_UNSIGNED__ */

static __inline void
_rune_wctype_init(_RuneLocale *rl)
{
	memcpy(&rl->rl_wctype, &_DefaultRuneLocale.rl_wctype,
	    sizeof(rl->rl_wctype));
}

static __inline void
_rune_wctrans_init(_RuneLocale *rl)
{
	rl->rl_wctrans[_WCTRANS_INDEX_LOWER].te_name   = "tolower";
	rl->rl_wctrans[_WCTRANS_INDEX_LOWER].te_cached = &rl->rl_maplower[0];
	rl->rl_wctrans[_WCTRANS_INDEX_LOWER].te_extmap = &rl->rl_maplower_ext;
	rl->rl_wctrans[_WCTRANS_INDEX_UPPER].te_name   = "toupper";
	rl->rl_wctrans[_WCTRANS_INDEX_UPPER].te_cached = &rl->rl_mapupper[0];
	rl->rl_wctrans[_WCTRANS_INDEX_UPPER].te_extmap = &rl->rl_mapupper_ext;
}

static __inline void
_rune_init_priv(_RuneLocalePriv *rlp)
{
#if _CTYPE_CACHE_SIZE != _CTYPE_NUM_CHARS
	int i;

	for (i = _CTYPE_CACHE_SIZE; i < _CTYPE_NUM_CHARS; ++i) {
		rlp->rlp_ctype_tab  [i + 1] = 0;
		rlp->rlp_tolower_tab[i + 1] = i;
		rlp->rlp_toupper_tab[i + 1] = i;

#ifdef __BUILD_LEGACY
		rlp->rlp_compat_bsdctype[i + 1] = 0;
#endif
	}
#endif
	rlp->rlp_ctype_tab  [0] = 0;
	rlp->rlp_tolower_tab[0] = EOF;
	rlp->rlp_toupper_tab[0] = EOF;

	rlp->rl.rl_ctype_tab   = (const unsigned short *)&rlp->rlp_ctype_tab[0];
	rlp->rl.rl_tolower_tab = (const short *)&rlp->rlp_tolower_tab[0];
	rlp->rl.rl_toupper_tab = (const short *)&rlp->rlp_toupper_tab[0];
	rlp->rl.rl_codeset     = (const char *)&rlp->rlp_codeset[0];

	_rune_wctype_init(&rlp->rl);
	_rune_wctrans_init(&rlp->rl);

#ifdef __BUILD_LEGACY
	rlp->rlp_compat_bsdctype[0] = 0;
	rlp->rl.rl_compat_bsdctype = (const unsigned char *)
	    &rlp->rlp_compat_bsdctype[0];
#endif
}

static __inline void
_rune_find_codeset(char *s, size_t n,
    char *var, size_t *plenvar)
{
	size_t lenvar;
	const char *endvar;

#define _RUNE_CODESET_LEN (sizeof(_RUNE_CODESET)-1)

	lenvar = *plenvar;
	for (/**/; lenvar > _RUNE_CODESET_LEN; ++var, --lenvar) {
		if (!memcmp(var, _RUNE_CODESET, _RUNE_CODESET_LEN)) {
			*var = '\0';
			*plenvar -= lenvar;
			endvar = &var[_RUNE_CODESET_LEN];
			while (n-- > 1 && lenvar-- > _RUNE_CODESET_LEN) {
				if (*endvar == ' ' || *endvar == '\t')
					break;
				*s++ = *endvar++;
			}
			break;
		}
	}
	*s = '\0';
}

#ifdef __BUILD_LEGACY
static __inline int
_runetype_to_bsdctype(_RuneType bits)
{
	int ret;

	if (bits == (_RuneType)0)
		return 0;
	ret = 0;
	if (bits & _RUNETYPE_U)
		ret |= _COMPAT_U;
	if (bits & _RUNETYPE_L)
		ret |= _COMPAT_L;
	if (bits & _RUNETYPE_D)
		ret |= _COMPAT_N;
	if (bits & _RUNETYPE_S)
		ret |= _COMPAT_S;
	if (bits & _RUNETYPE_P)
		ret |= _COMPAT_P;
	if (bits & _RUNETYPE_C)
		ret |= _COMPAT_C;
	if ((bits & (_RUNETYPE_X | _RUNETYPE_D)) == _RUNETYPE_X)
		ret |= _COMPAT_X;
	if ((bits & (_RUNETYPE_R | _RUNETYPE_G)) == _RUNETYPE_R)
		ret |= _COMPAT_B;
	return ret;
}
#endif /* __BUILD_LEGACY */

static __inline int
_rune_read_file(const char * __restrict var, size_t lenvar,
    _RuneLocale ** __restrict prl)
{
	int ret, i;
	const _FileRuneLocale *frl;
	const _FileRuneEntry *fre;
	const uint32_t *frune;
	_RuneLocalePriv *rlp;
	_RuneLocale *rl;
	_RuneEntry *re;
	uint32_t *rune;
	uint32_t runetype_len, maplower_len, mapupper_len, variable_len;
	size_t len, n;

	if (lenvar < sizeof(*frl))
		return EFTYPE;
	lenvar -= sizeof(*frl);
	frl = (const _FileRuneLocale *)(const void *)var;
	if (memcmp(_RUNECT10_MAGIC, &frl->frl_magic[0], sizeof(frl->frl_magic)))
		return EFTYPE;

	runetype_len = be32toh(frl->frl_runetype_ext.frr_nranges);
	maplower_len = be32toh(frl->frl_maplower_ext.frr_nranges);
	mapupper_len = be32toh(frl->frl_mapupper_ext.frr_nranges);
	len = runetype_len + maplower_len + mapupper_len;

	fre = (const _FileRuneEntry *)(const void *)(frl + 1);
	frune = (const uint32_t *)(const void *)(fre + len);

	variable_len = be32toh((uint32_t)frl->frl_variable_len);

	n = len * sizeof(*fre);
	if (lenvar < n)
		return EFTYPE;
	lenvar -= n;

	n = sizeof(*rlp) + (len * sizeof(*re)) + lenvar;
	rlp = (_RuneLocalePriv *)malloc(n);
	if (rlp == NULL)
		return ENOMEM;
#ifndef __CHAR_UNSIGNED__
	rlp->rlp_ctype_tab = NULL;
	rlp->rlp_tolower_tab = NULL;
	rlp->rlp_toupper_tab = NULL;
	if ((rlp->rlp_ctype_tab = alloc_guarded(sizeof(rlp->rlp_ctype_tab[0]),
		    _CTYPE_NUM_CHARS + 1)) == NULL ||
	    (rlp->rlp_tolower_tab =
		alloc_guarded(sizeof(rlp->rlp_tolower_tab[0]),
		    _CTYPE_NUM_CHARS + 1)) == NULL ||
	    (rlp->rlp_toupper_tab =
		alloc_guarded(sizeof(rlp->rlp_toupper_tab[0]),
		    _CTYPE_NUM_CHARS + 1)) == NULL) {
		ret = ENOMEM;
		goto err;
	}
#endif	/* !__CHAR_UNSIGNED__ */
	_rune_init_priv(rlp);

	rl = &rlp->rl;
	re = (_RuneEntry *)(void *)(rlp + 1);
	rune = (uint32_t *)(void *)(re + len);

	for (i = 0; i < _CTYPE_CACHE_SIZE; ++i) {
		rl->rl_runetype[i] = be32toh(frl->frl_runetype[i]);
		rl->rl_maplower[i] = be32toh((uint32_t)frl->frl_maplower[i]);
		rl->rl_mapupper[i] = be32toh((uint32_t)frl->frl_mapupper[i]);
	}

#define READ_RANGE(name)						\
do {									\
	const _FileRuneEntry *end_fre;					\
	const uint32_t *end_frune;					\
									\
	rl->rl_##name##_ext.rr_nranges = name##_len;			\
	rl->rl_##name##_ext.rr_rune_ranges = re;			\
									\
	end_fre = fre + name##_len;					\
	while (fre < end_fre) {						\
		re->re_min = be32toh((uint32_t)fre->fre_min);		\
		re->re_max = be32toh((uint32_t)fre->fre_max);		\
		re->re_map = be32toh((uint32_t)fre->fre_map);		\
		if (re->re_map != 0) {					\
			re->re_rune_types = NULL;			\
		} else {						\
			re->re_rune_types = rune;			\
			len = re->re_max - re->re_min + 1;		\
			n = len * sizeof(*frune);			\
			if (lenvar < n) {				\
				ret = EFTYPE;				\
				goto err;				\
			}						\
			lenvar -= n;					\
			end_frune = frune + len;			\
			while (frune < end_frune)			\
				*rune++ = be32toh(*frune++);		\
		}							\
		++fre, ++re;						\
	}								\
} while (0)

	READ_RANGE(runetype);
	READ_RANGE(maplower);
	READ_RANGE(mapupper);

	if (lenvar < variable_len) {
		ret = EFTYPE;
		goto err;
	}

	memcpy((void *)rune, (void const *)frune, variable_len);
	rl->rl_variable_len = variable_len;
	rl->rl_variable = (void *)rune;

	_rune_find_codeset(rlp->rlp_codeset, sizeof(rlp->rlp_codeset),
	    (char *)rl->rl_variable, &rl->rl_variable_len);

	ret = _citrus_ctype_open(&rl->rl_citrus_ctype, frl->frl_encoding,
	    rl->rl_variable, rl->rl_variable_len, _PRIVSIZE);
	if (ret)
		goto err;
	if (__mb_len_max_runtime <
	    _citrus_ctype_get_mb_cur_max(rl->rl_citrus_ctype)) {
		ret = EINVAL;
		goto err;
	}

	for (i = 0; i < _CTYPE_CACHE_SIZE; ++i) {
		wint_t wc;
		_RuneType rc;

		ret = _citrus_ctype_btowc(rl->rl_citrus_ctype, i, &wc);
		if (ret)
			goto err;
		if (wc == WEOF) {
			rlp->rlp_ctype_tab[i + 1] = 0;
			rlp->rlp_tolower_tab[i + 1] = i;
			rlp->rlp_toupper_tab[i + 1] = i;
		} else {
			rc = _runetype_priv(rl, wc);
			rlp->rlp_ctype_tab[i + 1] = (unsigned short)
			    ((rc & ~_RUNETYPE_SWM) >> 8);

#ifdef __BUILD_LEGACY
			rlp->rlp_compat_bsdctype[i + 1]
			  = _runetype_to_bsdctype(rc);
#endif

#define CONVERT_MAP(name)						\
do {									\
	wint_t map;							\
	int c;								\
									\
	map = _towctrans_priv(wc, _wctrans_##name(rl));			\
	if (map == wc || (_citrus_ctype_wctob(rl->rl_citrus_ctype,	\
	    map, &c)  || c == EOF))					\
		c = i;							\
	rlp->rlp_to##name##_tab[i + 1] = (short)c;			\
} while (0)

			CONVERT_MAP(lower);
			CONVERT_MAP(upper);
		}
	}
	*prl = rl;
	return 0;

err:
#ifndef __CHAR_UNSIGNED__
	free_guarded(rlp->rlp_ctype_tab, sizeof(rlp->rlp_ctype_tab[0]),
	    _CTYPE_NUM_CHARS + 1);
	free_guarded(rlp->rlp_tolower_tab, sizeof(rlp->rlp_tolower_tab[0]),
	    _CTYPE_NUM_CHARS + 1);
	free_guarded(rlp->rlp_toupper_tab, sizeof(rlp->rlp_toupper_tab[0]),
	    _CTYPE_NUM_CHARS + 1);
#endif
	free(rlp);
	return ret;
}

int
_rune_load(const char * __restrict var, size_t lenvar,
    _RuneLocale ** __restrict prl)
{
	int ret;

	_DIAGASSERT(var != NULL || lenvar < 1);
	_DIAGASSERT(prl != NULL);

	if (lenvar < 1)
		return EFTYPE;
	switch (*var) {
	case 'R':
		ret = _rune_read_file(var, lenvar, prl);
		break;
	default:
		ret = EFTYPE;
	}
	return ret;
}
