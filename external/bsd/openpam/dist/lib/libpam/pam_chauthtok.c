/*	$NetBSD: pam_chauthtok.c,v 1.4 2023/06/30 21:46:21 christos Exp $	*/

/*-
 * Copyright (c) 2002-2003 Networks Associates Technology, Inc.
 * Copyright (c) 2004-2017 Dag-Erling Smørgrav
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * Network Associates Laboratories, the Security Research Division of
 * Network Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/cdefs.h>
__RCSID("$NetBSD: pam_chauthtok.c,v 1.4 2023/06/30 21:46:21 christos Exp $");

#include <sys/param.h>

#include <security/pam_appl.h>

#include "openpam_impl.h"

/*
 * XSSO 4.2.1
 * XSSO 6 page 38
 *
 * Perform password related functions within the PAM framework
 */

int
pam_chauthtok(pam_handle_t *pamh,
	int flags)
{
	int r;

	ENTER();
	if (flags & ~(PAM_SILENT|PAM_CHANGE_EXPIRED_AUTHTOK))
		RETURNC(PAM_BAD_CONSTANT);
	r = openpam_dispatch(pamh, PAM_SM_CHAUTHTOK,
	    flags | PAM_PRELIM_CHECK);
	if (r == PAM_SUCCESS)
		r = openpam_dispatch(pamh, PAM_SM_CHAUTHTOK,
		    flags | PAM_UPDATE_AUTHTOK);
	pam_set_item(pamh, PAM_OLDAUTHTOK, NULL);
	pam_set_item(pamh, PAM_AUTHTOK, NULL);
	RETURNC(r);
}

/*
 * Error codes:
 *
 *	=openpam_dispatch
 *	=pam_sm_chauthtok
 *	!PAM_IGNORE
 *	PAM_BAD_CONSTANT
 */

/**
 * The =pam_chauthtok function attempts to change the authentication token
 * for the user associated with the pam context specified by the =pamh
 * argument.
 *
 * The =flags argument is the binary or of zero or more of the following
 * values:
 *
 *	=PAM_SILENT:
 *		Do not emit any messages.
 *	=PAM_CHANGE_EXPIRED_AUTHTOK:
 *		Change only those authentication tokens that have expired.
 *
 * If any other bits are set, =pam_chauthtok will return =PAM_BAD_CONSTANT.
 */
