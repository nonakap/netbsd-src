/*	$NetBSD: background.c,v 1.34 2024/12/23 02:58:03 blymn Exp $	*/

/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Julian Coleman.
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
#ifndef lint
__RCSID("$NetBSD: background.c,v 1.34 2024/12/23 02:58:03 blymn Exp $");
#endif				/* not lint */

#include <stdlib.h>
#include "curses.h"
#include "curses_private.h"

/*
 * bkgdset
 *	Set new background attributes on stdscr.
 */
void
bkgdset(chtype ch)
{
	wbkgdset(stdscr, ch);
}

/*
 * bkgd --
 *	Set new background attributes on stdscr and apply them to its
 *	contents.
 */
int
bkgd(chtype ch)
{
	return(wbkgd(stdscr, ch));
}

/*
 * wbkgdset
 *	Set new background attributes on the specified window.
 */
void
wbkgdset(WINDOW *win, chtype ch)
{
	__CTRACE(__CTRACE_ATTR, "wbkgdset: (%p), '%s', %08x\n",
	    win, unctrl(ch & __CHARTEXT), ch & __ATTRIBUTES);

	if (__predict_false(win == NULL))
		return;

	/* Background character. */
	if (ch & __CHARTEXT)
		win->bch = (wchar_t) ch & __CHARTEXT;

	/* Background attributes (check colour). */
	if (__using_color && !(ch & __COLOR))
		ch |= __default_color;
	win->battr = (attr_t) ch & __ATTRIBUTES;
}

/*
 * wbkgd --
 *	Set new background attributes on the specified window and
 *	apply them to its contents.
 */
int
wbkgd(WINDOW *win, chtype ch)
{
	int y, x;

	__CTRACE(__CTRACE_ATTR, "wbkgd: (%p), '%s', %08x\n",
	    win, unctrl(ch & __CHARTEXT), ch & __ATTRIBUTES);

	if (__predict_false(win == NULL))
		return ERR;

	wbkgdset(win, ch);

	for (y = 0; y < win->maxy; y++) {
		for (x = 0; x < win->maxx; x++) {
			__LDATA *cp = &win->alines[y]->line[x];

			/* Update/switch background characters */
			if (cp->cflags & CA_BACKGROUND)
				cp->ch = win->bch;

			/* Update/merge attributes */
			cp->attr = win->battr | (cp->attr & __ALTCHARSET);
#ifdef HAVE_WCHAR
			cp->wcols = 1;
#endif
		}
	}
	__touchwin(win, 1);
	return OK;
}

/*
 * getbkgd --
 *	Get current background attributes.
 */
chtype
getbkgd(WINDOW *win)
{
	attr_t	battr;

	if (__predict_false(win == NULL))
		return ERR;

	/* Background attributes (check colour). */
	battr = win->battr & A_ATTRIBUTES;
	if (__using_color && ((battr & __COLOR) == __default_color))
		battr &= ~__COLOR;

	return ((chtype) ((win->bch & A_CHARTEXT) | battr));
}


#ifdef HAVE_WCHAR

void
bkgrndset(const cchar_t *wch)
{
	wbkgrndset(stdscr, wch);
}


int
bkgrnd(const cchar_t *wch)
{
	return wbkgrnd(stdscr, wch);
}


int
getbkgrnd(cchar_t *wch)
{
	return wgetbkgrnd(stdscr, wch);
}


void
wbkgrndset(WINDOW *win, const cchar_t *wch)
{
	attr_t battr;
	nschar_t *np, *tnp;
	int i, wy, wx;
	__LDATA obkgrnd, nbkgrnd;
	__LINE *wlp;

	__CTRACE(__CTRACE_ATTR, "wbkgrndset: (%p), '%s', %x\n",
	    win, (const char *)wunctrl(wch), wch->attributes);

	if (__predict_false(win == NULL))
		return;

	/* ignore multi-column characters */
	if (!wch->elements || wcwidth(wch->vals[0]) > 1)
		return;

	/* get a copy of the old background, we will need it. */
	obkgrnd.ch = win->bch;
	obkgrnd.attr = win->battr;
	obkgrnd.cflags = CA_BACKGROUND;
	obkgrnd.wcols = win->wcols;
	obkgrnd.nsp = NULL;
	_cursesi_copy_nsp(win->bnsp, &obkgrnd);

	/* Background character. */
	tnp = np = win->bnsp;
	if (wcwidth( wch->vals[0]))
		win->bch = wch->vals[0];
	else {
		if (!np) {
			np = malloc(sizeof(nschar_t));
			if (!np)
				return;
			np->next = NULL;
			win->bnsp = np;
		}
		np->ch = wch->vals[0];
		tnp = np;
		np = np->next;
	}
	/* add non-spacing characters */
	if (wch->elements > 1) {
		for (i = 1; i < wch->elements; i++) {
			if ( !np ) {
				np = malloc(sizeof(nschar_t));
				if (!np)
					return;
				np->next = NULL;
				if (tnp)
					tnp->next = np;
				else
					win->bnsp = np;
			}
			np->ch = wch->vals[i];
			tnp = np;
			np = np->next;
		}
	}
	/* clear the old non-spacing characters */
	__cursesi_free_nsp(np);

	/* Background attributes (check colour). */
	battr = wch->attributes & WA_ATTRIBUTES;
	if (__using_color && !( battr & __COLOR))
		battr |= __default_color;
	win->battr = battr;
	win->wcols = 1;

	nbkgrnd.ch = win->bch;
	nbkgrnd.attr = win->battr;
	nbkgrnd.cflags = CA_BACKGROUND;
	nbkgrnd.wcols = win->wcols;
	nbkgrnd.nsp = NULL;
	_cursesi_copy_nsp(win->bnsp, &nbkgrnd);

	/* if the background is already this char then skip updating */
	if (_cursesi_celleq(&obkgrnd, &nbkgrnd))
		return;

	/*
	 * Now do the dirty work of updating all the locations
	 * that have the old background character with the new.
	 */

	for (wy = 0; wy < win->maxy; wy++) {
		wlp = win->alines[wy];
		for (wx = 0; wx < win->maxx; wx++) {
			if (wlp->line[wx].cflags & CA_BACKGROUND) {
				_cursesi_copy_wchar(&nbkgrnd, &wlp->line[wx]);
			}
		}
	}
	__touchwin(win, 0);

}


int
wbkgrnd(WINDOW *win, const cchar_t *wch)
{
	__CTRACE(__CTRACE_ATTR, "wbkgrnd: (%p), '%s', %x\n",
	    win, (const char *)wunctrl(wch), wch->attributes);

	if (__predict_false(win == NULL))
		return ERR;

	/* ignore multi-column characters */
	if (!wch->elements || wcwidth( wch->vals[ 0 ]) > 1)
		return ERR;

	wbkgrndset(win, wch);
	__touchwin(win, 1);
	return OK;
}


int
wgetbkgrnd(WINDOW *win, cchar_t *wch)
{
	nschar_t *np;

	if (__predict_false(win == NULL))
		return ERR;

	/* Background attributes (check colour). */
	wch->attributes = win->battr & WA_ATTRIBUTES;
	if (__using_color && ((wch->attributes & __COLOR) == __default_color))
		wch->attributes &= ~__COLOR;
	wch->vals[0] = win->bch;
	wch->elements = 1;
	np = win->bnsp;
	if (np) {
		while (np && wch->elements < CURSES_CCHAR_MAX) {
			wch->vals[wch->elements++] = np->ch;
			np = np->next;
		}
	}

	return OK;
}

#else  /* !HAVE_WCHAR */

void
bkgrndset(const cchar_t *wch)
{
	return;
}

int
bkgrnd(const cchar_t *wch)
{
	return ERR;
}


int
getbkgrnd(cchar_t *wch)
{
	return ERR;
}


void
wbkgrndset(WINDOW *win, const cchar_t *wch)
{
	return;
}


int
wbkgrnd(WINDOW *win, const cchar_t *wch)
{
	return ERR;
}


int
wgetbkgrnd(WINDOW *win, cchar_t *wch)
{
	return ERR;
}

#endif /* !HAVE_WCHAR */
