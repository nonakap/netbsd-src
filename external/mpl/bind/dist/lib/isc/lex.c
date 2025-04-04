/*	$NetBSD: lex.c,v 1.12 2025/01/26 16:25:37 christos Exp $	*/

/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

/*! \file */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/buffer.h>
#include <isc/file.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/parseint.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/util.h>

#include "errno2result.h"

typedef struct inputsource {
	isc_result_t result;
	bool is_file;
	bool need_close;
	bool at_eof;
	bool last_was_eol;
	isc_buffer_t *pushback;
	unsigned int ignored;
	void *input;
	char *name;
	unsigned long line;
	unsigned long saved_line;
	ISC_LINK(struct inputsource) link;
} inputsource;

#define LEX_MAGIC    ISC_MAGIC('L', 'e', 'x', '!')
#define VALID_LEX(l) ISC_MAGIC_VALID(l, LEX_MAGIC)

struct isc_lex {
	/* Unlocked. */
	unsigned int magic;
	isc_mem_t *mctx;
	size_t max_token;
	char *data;
	unsigned int comments;
	bool comment_ok;
	bool last_was_eol;
	unsigned int brace_count;
	unsigned int paren_count;
	unsigned int saved_paren_count;
	isc_lexspecials_t specials;
	LIST(struct inputsource) sources;
};

static isc_result_t
grow_data(isc_lex_t *lex, size_t *remainingp, char **currp, char **prevp) {
	char *tmp;

	tmp = isc_mem_get(lex->mctx, lex->max_token * 2 + 1);
	memmove(tmp, lex->data, lex->max_token + 1);
	*currp = tmp + (*currp - lex->data);
	if (*prevp != NULL) {
		*prevp = tmp + (*prevp - lex->data);
	}
	isc_mem_put(lex->mctx, lex->data, lex->max_token + 1);
	lex->data = tmp;
	*remainingp += lex->max_token;
	lex->max_token *= 2;
	return ISC_R_SUCCESS;
}

void
isc_lex_create(isc_mem_t *mctx, size_t max_token, isc_lex_t **lexp) {
	isc_lex_t *lex;

	/*
	 * Create a lexer.
	 */
	REQUIRE(lexp != NULL && *lexp == NULL);

	if (max_token == 0U) {
		max_token = 1;
	}

	lex = isc_mem_get(mctx, sizeof(*lex));
	lex->data = isc_mem_get(mctx, max_token + 1);
	lex->mctx = mctx;
	lex->max_token = max_token;
	lex->comments = 0;
	lex->comment_ok = true;
	lex->last_was_eol = true;
	lex->brace_count = 0;
	lex->paren_count = 0;
	lex->saved_paren_count = 0;
	memset(lex->specials, 0, 256);
	INIT_LIST(lex->sources);
	lex->magic = LEX_MAGIC;

	*lexp = lex;
}

void
isc_lex_destroy(isc_lex_t **lexp) {
	isc_lex_t *lex;

	/*
	 * Destroy the lexer.
	 */

	REQUIRE(lexp != NULL);
	lex = *lexp;
	*lexp = NULL;
	REQUIRE(VALID_LEX(lex));

	while (!EMPTY(lex->sources)) {
		RUNTIME_CHECK(isc_lex_close(lex) == ISC_R_SUCCESS);
	}
	if (lex->data != NULL) {
		isc_mem_put(lex->mctx, lex->data, lex->max_token + 1);
	}
	lex->magic = 0;
	isc_mem_put(lex->mctx, lex, sizeof(*lex));
}

unsigned int
isc_lex_getcomments(isc_lex_t *lex) {
	/*
	 * Return the current lexer commenting styles.
	 */

	REQUIRE(VALID_LEX(lex));

	return lex->comments;
}

void
isc_lex_setcomments(isc_lex_t *lex, unsigned int comments) {
	/*
	 * Set allowed lexer commenting styles.
	 */

	REQUIRE(VALID_LEX(lex));

	lex->comments = comments;
}

void
isc_lex_getspecials(isc_lex_t *lex, isc_lexspecials_t specials) {
	/*
	 * Put the current list of specials into 'specials'.
	 */

	REQUIRE(VALID_LEX(lex));

	memmove(specials, lex->specials, 256);
}

void
isc_lex_setspecials(isc_lex_t *lex, isc_lexspecials_t specials) {
	/*
	 * The characters in 'specials' are returned as tokens.  Along with
	 * whitespace, they delimit strings and numbers.
	 */

	REQUIRE(VALID_LEX(lex));

	memmove(lex->specials, specials, 256);
}

static isc_result_t
new_source(isc_lex_t *lex, bool is_file, bool need_close, void *input,
	   const char *name) {
	inputsource *source;

	source = isc_mem_get(lex->mctx, sizeof(*source));
	source->result = ISC_R_SUCCESS;
	source->is_file = is_file;
	source->need_close = need_close;
	source->at_eof = false;
	source->last_was_eol = lex->last_was_eol;
	source->input = input;
	source->name = isc_mem_strdup(lex->mctx, name);
	source->pushback = NULL;
	isc_buffer_allocate(lex->mctx, &source->pushback,
			    (unsigned int)lex->max_token);
	source->ignored = 0;
	source->line = 1;
	ISC_LIST_INITANDPREPEND(lex->sources, source, link);

	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_openfile(isc_lex_t *lex, const char *filename) {
	isc_result_t result;
	FILE *stream = NULL;

	/*
	 * Open 'filename' and make it the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	result = isc_stdio_open(filename, "r", &stream);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = new_source(lex, true, true, stream, filename);
	if (result != ISC_R_SUCCESS) {
		(void)fclose(stream);
	}
	return result;
}

isc_result_t
isc_lex_openstream(isc_lex_t *lex, FILE *stream) {
	char name[128];

	/*
	 * Make 'stream' the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	snprintf(name, sizeof(name), "stream-%p", stream);

	return new_source(lex, true, false, stream, name);
}

isc_result_t
isc_lex_openbuffer(isc_lex_t *lex, isc_buffer_t *buffer) {
	char name[128];

	/*
	 * Make 'buffer' the current input source for 'lex'.
	 */

	REQUIRE(VALID_LEX(lex));

	snprintf(name, sizeof(name), "buffer-%p", buffer);

	return new_source(lex, false, false, buffer, name);
}

isc_result_t
isc_lex_close(isc_lex_t *lex) {
	inputsource *source;

	/*
	 * Close the most recently opened object (i.e. file or buffer).
	 */

	REQUIRE(VALID_LEX(lex));

	source = HEAD(lex->sources);
	if (source == NULL) {
		return ISC_R_NOMORE;
	}

	ISC_LIST_UNLINK(lex->sources, source, link);
	lex->last_was_eol = source->last_was_eol;
	if (source->is_file) {
		if (source->need_close) {
			(void)fclose((FILE *)(source->input));
		}
	}
	isc_mem_free(lex->mctx, source->name);
	isc_buffer_free(&source->pushback);
	isc_mem_put(lex->mctx, source, sizeof(*source));

	return ISC_R_SUCCESS;
}

typedef enum {
	lexstate_start,
	lexstate_crlf,
	lexstate_string,
	lexstate_number,
	lexstate_maybecomment,
	lexstate_ccomment,
	lexstate_ccommentend,
	lexstate_eatline,
	lexstate_qstring,
	lexstate_btext,
	lexstate_vpair,
	lexstate_vpairstart,
	lexstate_qvpair,
} lexstate;

#define IWSEOL (ISC_LEXOPT_INITIALWS | ISC_LEXOPT_EOL)

static void
pushback(inputsource *source, int c) {
	REQUIRE(source->pushback->current > 0);
	if (c == EOF) {
		source->at_eof = false;
		return;
	}
	source->pushback->current--;
	if (c == '\n') {
		source->line--;
	}
}

static isc_result_t
pushandgrow(isc_lex_t *lex, inputsource *source, int c) {
	if (isc_buffer_availablelength(source->pushback) == 0) {
		isc_buffer_t *tbuf = NULL;
		unsigned int oldlen;
		isc_region_t used;
		isc_result_t result;

		oldlen = isc_buffer_length(source->pushback);
		isc_buffer_allocate(lex->mctx, &tbuf, oldlen * 2);
		isc_buffer_usedregion(source->pushback, &used);
		result = isc_buffer_copyregion(tbuf, &used);
		INSIST(result == ISC_R_SUCCESS);
		tbuf->current = source->pushback->current;
		isc_buffer_free(&source->pushback);
		source->pushback = tbuf;
	}
	isc_buffer_putuint8(source->pushback, (uint8_t)c);
	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_gettoken(isc_lex_t *lex, unsigned int options, isc_token_t *tokenp) {
	inputsource *source;
	int c;
	bool done = false;
	bool no_comments = false;
	bool escaped = false;
	lexstate state = lexstate_start;
	lexstate saved_state = lexstate_start;
	isc_buffer_t *buffer;
	FILE *stream;
	char *curr, *prev;
	size_t remaining;
	uint32_t as_ulong;
	unsigned int saved_options;
	isc_result_t result;

	/*
	 * Get the next token.
	 */

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);
	REQUIRE(tokenp != NULL);

	if (source == NULL) {
		if ((options & ISC_LEXOPT_NOMORE) != 0) {
			tokenp->type = isc_tokentype_nomore;
			return ISC_R_SUCCESS;
		}
		return ISC_R_NOMORE;
	}

	if (source->result != ISC_R_SUCCESS) {
		return source->result;
	}

	lex->saved_paren_count = lex->paren_count;
	source->saved_line = source->line;

	if (isc_buffer_remaininglength(source->pushback) == 0 && source->at_eof)
	{
		if ((options & ISC_LEXOPT_DNSMULTILINE) != 0 &&
		    lex->paren_count != 0)
		{
			lex->paren_count = 0;
			return ISC_R_UNBALANCED;
		}
		if ((options & ISC_LEXOPT_BTEXT) != 0 && lex->brace_count != 0)
		{
			lex->brace_count = 0;
			return ISC_R_UNBALANCED;
		}
		if ((options & ISC_LEXOPT_EOF) != 0) {
			tokenp->type = isc_tokentype_eof;
			return ISC_R_SUCCESS;
		}
		return ISC_R_EOF;
	}

	isc_buffer_compact(source->pushback);

	saved_options = options;
	if ((options & ISC_LEXOPT_DNSMULTILINE) != 0 && lex->paren_count > 0) {
		options &= ~IWSEOL;
	}

	curr = lex->data;
	*curr = '\0';

	prev = NULL;
	remaining = lex->max_token;

#ifdef HAVE_FLOCKFILE
	if (source->is_file) {
		flockfile(source->input);
	}
#endif /* ifdef HAVE_FLOCKFILE */

	do {
		if (isc_buffer_remaininglength(source->pushback) == 0) {
			if (source->is_file) {
				stream = source->input;

#if defined(HAVE_FLOCKFILE) && defined(HAVE_GETC_UNLOCKED)
				c = getc_unlocked(stream);
#else  /* if defined(HAVE_FLOCKFILE) && defined(HAVE_GETC_UNLOCKED) */
				c = getc(stream);
#endif /* if defined(HAVE_FLOCKFILE) && defined(HAVE_GETC_UNLOCKED) */
				if (c == EOF) {
					if (ferror(stream)) {
						source->result =
							isc__errno2result(
								errno);
						result = source->result;
						goto done;
					}
					source->at_eof = true;
				}
			} else {
				buffer = source->input;

				if (buffer->current == buffer->used) {
					c = EOF;
					source->at_eof = true;
				} else {
					c = *((unsigned char *)buffer->base +
					      buffer->current);
					buffer->current++;
				}
			}
			if (c != EOF) {
				source->result = pushandgrow(lex, source, c);
				if (source->result != ISC_R_SUCCESS) {
					result = source->result;
					goto done;
				}
			}
		}

		if (!source->at_eof) {
			if (state == lexstate_start) {
				/* Token has not started yet. */
				source->ignored = isc_buffer_consumedlength(
					source->pushback);
			}
			c = isc_buffer_getuint8(source->pushback);
		} else {
			c = EOF;
		}

		if (c == '\n') {
			source->line++;
		}

		if (lex->comment_ok && !no_comments) {
			if (!escaped && c == ';' &&
			    ((lex->comments & ISC_LEXCOMMENT_DNSMASTERFILE) !=
			     0))
			{
				saved_state = state;
				state = lexstate_eatline;
				no_comments = true;
				continue;
			} else if (c == '/' &&
				   (lex->comments &
				    (ISC_LEXCOMMENT_C |
				     ISC_LEXCOMMENT_CPLUSPLUS)) != 0)
			{
				saved_state = state;
				state = lexstate_maybecomment;
				no_comments = true;
				continue;
			} else if (c == '#' && ((lex->comments &
						 ISC_LEXCOMMENT_SHELL) != 0))
			{
				saved_state = state;
				state = lexstate_eatline;
				no_comments = true;
				continue;
			}
		}

	no_read:
		/* INSIST(c == EOF || (c >= 0 && c <= 255)); */
		switch (state) {
		case lexstate_start:
			if (c == EOF) {
				lex->last_was_eol = false;
				if ((options & ISC_LEXOPT_DNSMULTILINE) != 0 &&
				    lex->paren_count != 0)
				{
					lex->paren_count = 0;
					result = ISC_R_UNBALANCED;
					goto done;
				}
				if ((options & ISC_LEXOPT_BTEXT) != 0 &&
				    lex->brace_count != 0)
				{
					lex->brace_count = 0;
					result = ISC_R_UNBALANCED;
					goto done;
				}
				if ((options & ISC_LEXOPT_EOF) == 0) {
					result = ISC_R_EOF;
					goto done;
				}
				tokenp->type = isc_tokentype_eof;
				done = true;
			} else if (c == ' ' || c == '\t') {
				if (lex->last_was_eol &&
				    (options & ISC_LEXOPT_INITIALWS) != 0)
				{
					lex->last_was_eol = false;
					tokenp->type = isc_tokentype_initialws;
					tokenp->value.as_char = c;
					done = true;
				}
			} else if (c == '\n') {
				if ((options & ISC_LEXOPT_EOL) != 0) {
					tokenp->type = isc_tokentype_eol;
					done = true;
				}
				lex->last_was_eol = true;
			} else if (c == '\r') {
				if ((options & ISC_LEXOPT_EOL) != 0) {
					state = lexstate_crlf;
				}
			} else if (c == '"' &&
				   (options & ISC_LEXOPT_QSTRING) != 0)
			{
				lex->last_was_eol = false;
				no_comments = true;
				state = lexstate_qstring;
			} else if (lex->specials[c]) {
				lex->last_was_eol = false;
				if ((c == '(' || c == ')') &&
				    (options & ISC_LEXOPT_DNSMULTILINE) != 0)
				{
					if (c == '(') {
						if (lex->paren_count == 0) {
							options &= ~IWSEOL;
						}
						lex->paren_count++;
					} else {
						if (lex->paren_count == 0) {
							result =
								ISC_R_UNBALANCED;
							goto done;
						}
						lex->paren_count--;
						if (lex->paren_count == 0) {
							options = saved_options;
						}
					}
					continue;
				} else if (c == '{' &&
					   (options & ISC_LEXOPT_BTEXT) != 0)
				{
					if (lex->brace_count != 0) {
						result = ISC_R_UNBALANCED;
						goto done;
					}
					lex->brace_count++;
					options &= ~IWSEOL;
					state = lexstate_btext;
					no_comments = true;
					continue;
				}
				tokenp->type = isc_tokentype_special;
				tokenp->value.as_char = c;
				done = true;
			} else if (isdigit((unsigned char)c) &&
				   (options & ISC_LEXOPT_NUMBER) != 0)
			{
				lex->last_was_eol = false;
				if ((options & ISC_LEXOPT_OCTAL) != 0 &&
				    (c == '8' || c == '9'))
				{
					state = lexstate_string;
				} else {
					state = lexstate_number;
				}
				goto no_read;
			} else {
				lex->last_was_eol = false;
				state = lexstate_string;
				goto no_read;
			}
			break;
		case lexstate_crlf:
			if (c != '\n') {
				pushback(source, c);
			}
			tokenp->type = isc_tokentype_eol;
			done = true;
			lex->last_was_eol = true;
			break;
		case lexstate_number:
			if (c == EOF || !isdigit((unsigned char)c)) {
				if (c == ' ' || c == '\t' || c == '\r' ||
				    c == '\n' || c == EOF || lex->specials[c])
				{
					int base;
					if ((options & ISC_LEXOPT_OCTAL) != 0) {
						base = 8;
					} else if ((options &
						    ISC_LEXOPT_CNUMBER) != 0)
					{
						base = 0;
					} else {
						base = 10;
					}
					pushback(source, c);

					result = isc_parse_uint32(
						&as_ulong, lex->data, base);
					if (result == ISC_R_SUCCESS) {
						tokenp->type =
							isc_tokentype_number;
						tokenp->value.as_ulong =
							as_ulong;
					} else if (result == ISC_R_BADNUMBER) {
						isc_tokenvalue_t *v;

						tokenp->type =
							isc_tokentype_string;
						v = &(tokenp->value);
						v->as_textregion.base =
							lex->data;
						v->as_textregion.length =
							(unsigned int)(lex->max_token -
								       remaining);
					} else {
						goto done;
					}
					done = true;
					continue;
				} else if ((options & ISC_LEXOPT_CNUMBER) ==
						   0 ||
					   ((c != 'x' && c != 'X') ||
					    (curr != &lex->data[1]) ||
					    (lex->data[0] != '0')))
				{
					/* Above test supports hex numbers */
					state = lexstate_string;
				}
			} else if ((options & ISC_LEXOPT_OCTAL) != 0 &&
				   (c == '8' || c == '9'))
			{
				state = lexstate_string;
			}
			if (remaining == 0U) {
				result = grow_data(lex, &remaining, &curr,
						   &prev);
				if (result != ISC_R_SUCCESS) {
					goto done;
				}
			}
			INSIST(remaining > 0U);
			*curr++ = c;
			*curr = '\0';
			remaining--;
			break;
		case lexstate_string:
			if (!escaped && c == '=' &&
			    (options & ISC_LEXOPT_VPAIR) != 0)
			{
				if (remaining == 0U) {
					result = grow_data(lex, &remaining,
							   &curr, &prev);
					if (result != ISC_R_SUCCESS) {
						goto done;
					}
				}
				INSIST(remaining > 0U);
				*curr++ = c;
				*curr = '\0';
				remaining--;
				state = lexstate_vpairstart;
				break;
			}
			FALLTHROUGH;
		case lexstate_vpairstart:
			if (state == lexstate_vpairstart) {
				if (c == '"' &&
				    (options & ISC_LEXOPT_QVPAIR) != 0)
				{
					no_comments = true;
					state = lexstate_qvpair;
					break;
				}
				state = lexstate_vpair;
			}
			FALLTHROUGH;
		case lexstate_vpair:
			/*
			 * EOF needs to be checked before lex->specials[c]
			 * as lex->specials[EOF] is not a good idea.
			 */
			if (c == '\r' || c == '\n' || c == EOF ||
			    (!escaped &&
			     (c == ' ' || c == '\t' || lex->specials[c])))
			{
				pushback(source, c);
				if (source->result != ISC_R_SUCCESS) {
					result = source->result;
					goto done;
				}
				if (escaped && c == EOF) {
					result = ISC_R_UNEXPECTEDEND;
					goto done;
				}
				tokenp->type = (state == lexstate_string)
						       ? isc_tokentype_string
						       : isc_tokentype_vpair;
				tokenp->value.as_textregion.base = lex->data;
				tokenp->value.as_textregion.length =
					(unsigned int)(lex->max_token -
						       remaining);
				done = true;
				continue;
			}
			if ((options & ISC_LEXOPT_ESCAPE) != 0) {
				escaped = (!escaped && c == '\\') ? true
								  : false;
			}
			if (remaining == 0U) {
				result = grow_data(lex, &remaining, &curr,
						   &prev);
				if (result != ISC_R_SUCCESS) {
					goto done;
				}
			}
			INSIST(remaining > 0U);
			*curr++ = c;
			*curr = '\0';
			remaining--;
			break;
		case lexstate_maybecomment:
			if (c == '*' && (lex->comments & ISC_LEXCOMMENT_C) != 0)
			{
				state = lexstate_ccomment;
				continue;
			} else if (c == '/' && (lex->comments &
						ISC_LEXCOMMENT_CPLUSPLUS) != 0)
			{
				state = lexstate_eatline;
				continue;
			}
			pushback(source, c);
			c = '/';
			no_comments = false;
			state = saved_state;
			goto no_read;
		case lexstate_ccomment:
			if (c == EOF) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			if (c == '*') {
				state = lexstate_ccommentend;
			}
			break;
		case lexstate_ccommentend:
			if (c == EOF) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			if (c == '/') {
				/*
				 * C-style comments become a single space.
				 * We do this to ensure that a comment will
				 * act as a delimiter for strings and
				 * numbers.
				 */
				c = ' ';
				no_comments = false;
				state = saved_state;
				goto no_read;
			} else if (c != '*') {
				state = lexstate_ccomment;
			}
			break;
		case lexstate_eatline:
			if ((c == '\n') || (c == EOF)) {
				no_comments = false;
				state = saved_state;
				goto no_read;
			}
			break;
		case lexstate_qstring:
		case lexstate_qvpair:
			if (c == EOF) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			if (c == '"') {
				if (escaped) {
					escaped = false;
					/*
					 * Overwrite the preceding backslash.
					 */
					INSIST(prev != NULL);
					*prev = '"';
				} else {
					tokenp->type =
						(state == lexstate_qstring)
							? isc_tokentype_qstring
							: isc_tokentype_qvpair;
					tokenp->value.as_textregion.base =
						lex->data;
					tokenp->value.as_textregion.length =
						(unsigned int)(lex->max_token -
							       remaining);
					no_comments = false;
					done = true;
				}
			} else {
				if (c == '\n' && !escaped &&
				    (options & ISC_LEXOPT_QSTRINGMULTILINE) ==
					    0)
				{
					pushback(source, c);
					result = ISC_R_UNBALANCEDQUOTES;
					goto done;
				}
				if (c == '\\' && !escaped) {
					escaped = true;
				} else {
					escaped = false;
				}
				if (remaining == 0U) {
					result = grow_data(lex, &remaining,
							   &curr, &prev);
					if (result != ISC_R_SUCCESS) {
						goto done;
					}
				}
				INSIST(remaining > 0U);
				prev = curr;
				*curr++ = c;
				*curr = '\0';
				remaining--;
			}
			break;
		case lexstate_btext:
			if (c == EOF) {
				result = ISC_R_UNEXPECTEDEND;
				goto done;
			}
			if (c == '{') {
				if (escaped) {
					escaped = false;
				} else {
					lex->brace_count++;
				}
			} else if (c == '}') {
				if (escaped) {
					escaped = false;
				} else {
					INSIST(lex->brace_count > 0);
					lex->brace_count--;
				}

				if (lex->brace_count == 0) {
					tokenp->type = isc_tokentype_btext;
					tokenp->value.as_textregion.base =
						lex->data;
					tokenp->value.as_textregion.length =
						(unsigned int)(lex->max_token -
							       remaining);
					no_comments = false;
					done = true;
					break;
				}
			}

			if (c == '\\' && !escaped) {
				escaped = true;
			} else {
				escaped = false;
			}

			if (remaining == 0U) {
				result = grow_data(lex, &remaining, &curr,
						   &prev);
				if (result != ISC_R_SUCCESS) {
					goto done;
				}
			}
			INSIST(remaining > 0U);
			prev = curr;
			*curr++ = c;
			*curr = '\0';
			remaining--;
			break;
		default:
			FATAL_ERROR("Unexpected state %d", state);
		}
	} while (!done);

	result = ISC_R_SUCCESS;
done:
#ifdef HAVE_FLOCKFILE
	if (source->is_file) {
		funlockfile(source->input);
	}
#endif /* ifdef HAVE_FLOCKFILE */
	return result;
}

isc_result_t
isc_lex_getmastertoken(isc_lex_t *lex, isc_token_t *token,
		       isc_tokentype_t expect, bool eol) {
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
			       ISC_LEXOPT_DNSMULTILINE | ISC_LEXOPT_ESCAPE;
	isc_result_t result;

	if (expect == isc_tokentype_vpair) {
		options |= ISC_LEXOPT_VPAIR;
	} else if (expect == isc_tokentype_qvpair) {
		options |= ISC_LEXOPT_VPAIR;
		options |= ISC_LEXOPT_QVPAIR;
	} else if (expect == isc_tokentype_qstring) {
		options |= ISC_LEXOPT_QSTRING;
	} else if (expect == isc_tokentype_number) {
		options |= ISC_LEXOPT_NUMBER;
	}
	result = isc_lex_gettoken(lex, options, token);
	if (result == ISC_R_RANGE) {
		isc_lex_ungettoken(lex, token);
	}
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (eol && ((token->type == isc_tokentype_eol) ||
		    (token->type == isc_tokentype_eof)))
	{
		return ISC_R_SUCCESS;
	}
	if (token->type == isc_tokentype_string &&
	    (expect == isc_tokentype_qstring || expect == isc_tokentype_qvpair))
	{
		return ISC_R_SUCCESS;
	}
	if (token->type == isc_tokentype_vpair &&
	    expect == isc_tokentype_qvpair)
	{
		return ISC_R_SUCCESS;
	}
	if (token->type != expect) {
		isc_lex_ungettoken(lex, token);
		if (token->type == isc_tokentype_eol ||
		    token->type == isc_tokentype_eof)
		{
			return ISC_R_UNEXPECTEDEND;
		}
		if (expect == isc_tokentype_number) {
			return ISC_R_BADNUMBER;
		}
		return ISC_R_UNEXPECTEDTOKEN;
	}
	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_getoctaltoken(isc_lex_t *lex, isc_token_t *token, bool eol) {
	unsigned int options = ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
			       ISC_LEXOPT_DNSMULTILINE | ISC_LEXOPT_ESCAPE |
			       ISC_LEXOPT_NUMBER | ISC_LEXOPT_OCTAL;
	isc_result_t result;

	result = isc_lex_gettoken(lex, options, token);
	if (result == ISC_R_RANGE) {
		isc_lex_ungettoken(lex, token);
	}
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	if (eol && ((token->type == isc_tokentype_eol) ||
		    (token->type == isc_tokentype_eof)))
	{
		return ISC_R_SUCCESS;
	}
	if (token->type != isc_tokentype_number) {
		isc_lex_ungettoken(lex, token);
		if (token->type == isc_tokentype_eol ||
		    token->type == isc_tokentype_eof)
		{
			return ISC_R_UNEXPECTEDEND;
		}
		return ISC_R_BADNUMBER;
	}
	return ISC_R_SUCCESS;
}

void
isc_lex_ungettoken(isc_lex_t *lex, isc_token_t *tokenp) {
	inputsource *source;
	/*
	 * Unget the current token.
	 */

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);
	REQUIRE(source != NULL);
	REQUIRE(tokenp != NULL);
	REQUIRE(isc_buffer_consumedlength(source->pushback) != 0 ||
		tokenp->type == isc_tokentype_eof);

	UNUSED(tokenp);

	isc_buffer_first(source->pushback);
	lex->paren_count = lex->saved_paren_count;
	source->line = source->saved_line;
	source->at_eof = false;
}

void
isc_lex_getlasttokentext(isc_lex_t *lex, isc_token_t *tokenp, isc_region_t *r) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);
	REQUIRE(source != NULL);
	REQUIRE(tokenp != NULL);
	REQUIRE(isc_buffer_consumedlength(source->pushback) != 0 ||
		tokenp->type == isc_tokentype_eof);

	UNUSED(tokenp);

	INSIST(source->ignored <= isc_buffer_consumedlength(source->pushback));
	r->base = (unsigned char *)isc_buffer_base(source->pushback) +
		  source->ignored;
	r->length = isc_buffer_consumedlength(source->pushback) -
		    source->ignored;
}

char *
isc_lex_getsourcename(isc_lex_t *lex) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);

	if (source == NULL) {
		return NULL;
	}

	return source->name;
}

unsigned long
isc_lex_getsourceline(isc_lex_t *lex) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);

	if (source == NULL) {
		return 0;
	}

	return source->line;
}

isc_result_t
isc_lex_setsourcename(isc_lex_t *lex, const char *name) {
	inputsource *source;
	char *newname;

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);

	if (source == NULL) {
		return ISC_R_NOTFOUND;
	}
	newname = isc_mem_strdup(lex->mctx, name);
	isc_mem_free(lex->mctx, source->name);
	source->name = newname;
	return ISC_R_SUCCESS;
}

isc_result_t
isc_lex_setsourceline(isc_lex_t *lex, unsigned long line) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));
	source = HEAD(lex->sources);

	if (source == NULL) {
		return ISC_R_NOTFOUND;
	}

	source->line = line;
	return ISC_R_SUCCESS;
}

bool
isc_lex_isfile(isc_lex_t *lex) {
	inputsource *source;

	REQUIRE(VALID_LEX(lex));

	source = HEAD(lex->sources);

	if (source == NULL) {
		return false;
	}

	return source->is_file;
}
