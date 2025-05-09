/*	$NetBSD: time.h,v 1.4 2025/01/26 16:25:43 christos Exp $	*/

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

#pragma once

/*! \file */

#include <inttypes.h>
#include <time.h>

#include <isc/attributes.h>
#include <isc/lang.h>
#include <isc/types.h>

/*
 * Define various time conversion constants.
 */
ISC_CONSTEXPR unsigned int MS_PER_SEC = 1000;
ISC_CONSTEXPR unsigned int US_PER_MS = 1000;
ISC_CONSTEXPR unsigned int NS_PER_US = 1000;
ISC_CONSTEXPR unsigned int US_PER_SEC = 1000 * 1000;
ISC_CONSTEXPR unsigned int NS_PER_MS = 1000 * 1000;
ISC_CONSTEXPR unsigned int NS_PER_SEC = 1000 * 1000 * 1000;

/*
 * ISC_FORMATHTTPTIMESTAMP_SIZE needs to be 30 in C locale and potentially
 * more for other locales to handle longer national abbreviations when
 * expanding strftime's %a and %b.
 */
#define ISC_FORMATHTTPTIMESTAMP_SIZE 50

/*
 * Semantic shims to distinguish between relative and absolute time
 */
#define isc_interval_zero isc_time_epoch
#define isc_interval_t	  isc_time_t

ISC_LANG_BEGINDECLS

#define isc_interval_set(i, seconds, nanoseconds) \
	isc_time_set((isc_time_t *)i, seconds, nanoseconds)
/*%<
 * Set 'i' to a value representing an interval of 'seconds' seconds and
 * 'nanoseconds' nanoseconds, suitable for use in isc_time_add() and
 * isc_time_subtract().
 *
 * Requires:
 *
 *\li	't' is a valid pointer.
 *\li	nanoseconds < 1000000000.
 */

#define isc_interval_iszero(i) isc_time_isepoch((const isc_time_t *)i)
/*%<
 * Returns true iff. 'i' is the zero interval.
 *
 * Requires:
 *
 *\li	'i' is a valid pointer.
 */

#define isc_interval_ms(i) isc_time_miliseconds((const isc_time_t *)i)
/*%<
 * Returns interval 'i' expressed as a number of milliseconds.
 *
 * Requires:
 *
 *\li	'i' is a valid pointer.
 */

#define isc_interval_fromnanosecs(ns) isc_time_fromnanosecs(ns)
#define isc_interval_tonanosecs(i)    isc_time_tonanosecs(i)

/***
 *** Absolute Times
 ***/

/*%
 * A linear count of nanoseconds.
 *
 * 64 bits of nanoseconds is more than 500 years.
 */
typedef uint64_t isc_nanosecs_t;

/*%
 * Convert linear nanoseconds to an isc_time_t
 */
#define isc_nanosecs_fromtime(time) \
	(NS_PER_SEC * (isc_nanosecs_t)(time).seconds + (time).nanoseconds)

/*%
 * Construct an isc_time_t from linear nanoseconds
 */
#define isc_time_fromnanosecs(ns)                 \
	((isc_time_t){                            \
		.seconds = (ns) / NS_PER_SEC,     \
		.nanoseconds = (ns) % NS_PER_SEC, \
	})

/*%
 * The contents of this structure are private, and MUST NOT be accessed
 * directly by callers.
 *
 * The contents are exposed only to allow callers to avoid dynamic allocation.
 */

struct isc_time {
	unsigned int seconds;
	unsigned int nanoseconds;
};

extern const isc_time_t *const isc_time_epoch;

void
isc_time_set(isc_time_t *t, unsigned int seconds, unsigned int nanoseconds);
/*%<
 * Set 't' to a value which represents the given number of seconds and
 * nanoseconds since 00:00:00 January 1, 1970, UTC.
 *
 * Notes:
 *\li	The Unix version of this call is equivalent to:
 *\code
 *	isc_time_settoepoch(t);
 *	isc_interval_set(i, seconds, nanoseconds);
 *	isc_time_add(t, i, t);
 *\endcode
 *
 * Requires:
 *\li	't' is a valid pointer.
 *\li	nanoseconds < 1000000000.
 */

void
isc_time_settoepoch(isc_time_t *t);
/*%<
 * Set 't' to the time of the epoch.
 *
 * Notes:
 *\li	The date of the epoch is platform-dependent.
 *
 * Requires:
 *
 *\li	't' is a valid pointer.
 */

bool
isc_time_isepoch(const isc_time_t *t);
/*%<
 * Returns true iff. 't' is the epoch ("time zero").
 *
 * Requires:
 *
 *\li	't' is a valid pointer.
 */

isc_nanosecs_t
isc_time_monotonic(void);
/*%<
 * Returns the system's monotonic time in linear nanoseconds.
 */

isc_time_t
isc_time_now(void);
/*%<
 * Set 't' to the current absolute time.
 *
 * Requires:
 *
 *\li	't' is a valid pointer.
 *
 * Returns:
 *
 *\li	Success
 *\li	Unexpected error
 *		Getting the time from the system failed.
 *\li	Out of range
 *		The time from the system is too large to be represented
 *		in the current definition of isc_time_t.
 */

isc_time_t
isc_time_now_hires(void);
/*%<
 * Set 't' to the current absolute time. Uses higher resolution clocks
 * recommended when microsecond accuracy is required.
 *
 * Requires:
 *
 *\li	't' is a valid pointer.
 *
 * Returns:
 *
 *\li	Success
 *\li	Unexpected error
 *		Getting the time from the system failed.
 *\li	Out of range
 *		The time from the system is too large to be represented
 *		in the current definition of isc_time_t.
 */

isc_result_t
isc_time_nowplusinterval(isc_time_t *t, const isc_interval_t *i);
/*%<
 * Set *t to the current absolute time + i.
 *
 * Note:
 *\li	This call is equivalent to:
 *
 *\code
 *		isc_time_now(t);
 *		isc_time_add(t, i, t);
 *\endcode
 *
 * Requires:
 *
 *\li	't' and 'i' are valid pointers.
 *
 * Returns:
 *
 *\li	Success
 *\li	Unexpected error
 *		Getting the time from the system failed.
 *\li	Out of range
 *		The interval added to the time from the system is too large to
 *		be represented in the current definition of isc_time_t.
 */

int
isc_time_compare(const isc_time_t *t1, const isc_time_t *t2);
/*%<
 * Compare the times referenced by 't1' and 't2'
 *
 * Requires:
 *
 *\li	't1' and 't2' are valid pointers.
 *
 * Returns:
 *
 *\li	-1		t1 < t2		(comparing times, not pointers)
 *\li	0		t1 = t2
 *\li	1		t1 > t2
 */

isc_result_t
isc_time_add(const isc_time_t *t, const isc_interval_t *i, isc_time_t *result);
/*%<
 * Add 'i' to 't', storing the result in 'result'.
 *
 * Requires:
 *
 *\li	't', 'i', and 'result' are valid pointers.
 *
 * Returns:
 *\li	Success
 *\li	Out of range
 * 		The interval added to the time is too large to
 *		be represented in the current definition of isc_time_t.
 */

isc_result_t
isc_time_subtract(const isc_time_t *t, const isc_interval_t *i,
		  isc_time_t *result);
/*%<
 * Subtract 'i' from 't', storing the result in 'result'.
 *
 * Requires:
 *
 *\li	't', 'i', and 'result' are valid pointers.
 *
 * Returns:
 *\li	Success
 *\li	Out of range
 *		The interval is larger than the time since the epoch.
 */

uint64_t
isc_time_microdiff(const isc_time_t *t1, const isc_time_t *t2);
/*%<
 * Find the difference in microseconds between time t1 and time t2.
 * t2 is the subtrahend of t1; ie, difference = t1 - t2.
 *
 * Requires:
 *
 *\li	't1' and 't2' are valid pointers.
 *
 * Returns:
 *\li	The difference of t1 - t2, or 0 if t1 <= t2.
 */

uint32_t
isc_time_seconds(const isc_time_t *t);
/*%<
 * Return the number of seconds since the epoch stored in a time structure.
 *
 * Requires:
 *
 *\li	't' is a valid pointer.
 */

isc_result_t
isc_time_secondsastimet(const isc_time_t *t, time_t *secondsp);
/*%<
 * Ensure the number of seconds in an isc_time_t is representable by a time_t.
 *
 * Notes:
 *\li	The number of seconds stored in an isc_time_t might be larger
 *	than the number of seconds a time_t is able to handle.  Since
 *	time_t is mostly opaque according to the ANSI/ISO standard
 *	(essentially, all you can be sure of is that it is an arithmetic type,
 *	not even necessarily integral), it can be tricky to ensure that
 *	the isc_time_t is in the range a time_t can handle.  Use this
 *	function in place of isc_time_seconds() any time you need to set a
 *	time_t from an isc_time_t.
 *
 * Requires:
 *\li	't' is a valid pointer.
 *
 * Returns:
 *\li	Success
 *\li	Out of range
 */

uint32_t
isc_time_nanoseconds(const isc_time_t *t);
/*%<
 * Return the number of nanoseconds stored in a time structure.
 *
 * Notes:
 *\li	This is the number of nanoseconds in excess of the number
 *	of seconds since the epoch; it will always be less than one
 *	full second.
 *
 * Requires:
 *\li	't' is a valid pointer.
 *
 * Ensures:
 *\li	The returned value is less than 1*10^9.
 */

uint32_t
isc_time_miliseconds(const isc_time_t *t);
/*%<
 * Returns time 't' expressed as a number of milliseconds.
 *
 * Requires:
 *
 *\li	't' is a valid pointer.
 */

void
isc_time_formattimestamp(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using a format like "30-Aug-2000 04:06:47.997" and the local time zone.
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

void
isc_time_formathttptimestamp(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using a format like "Mon, 30 Aug 2000 04:06:47 GMT"
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

isc_result_t
isc_time_parsehttptimestamp(char *input, isc_time_t *t);
/*%<
 * Parse the time in 'input' into the isc_time_t pointed to by 't',
 * expecting a format like "Mon, 30 Aug 2000 04:06:47 GMT"
 *
 *  Requires:
 *\li      'buf' and 't' are not NULL.
 */

void
isc_time_formatISO8601L(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using the ISO8601 format: "yyyy-mm-ddThh:mm:ss"
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

void
isc_time_formatISO8601Lms(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using the ISO8601 format: "yyyy-mm-ddThh:mm:ss.sss"
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

void
isc_time_formatISO8601Lus(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using the ISO8601 format: "yyyy-mm-ddThh:mm:ss.ssssss"
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

void
isc_time_formatISO8601(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using the ISO8601 format: "yyyy-mm-ddThh:mm:ssZ"
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

void
isc_time_formatISO8601ms(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using the ISO8601 format: "yyyy-mm-ddThh:mm:ss.sssZ"
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

void
isc_time_formatISO8601us(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using the ISO8601 format: "yyyy-mm-ddThh:mm:ss.ssssssZ"
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

void
isc_time_formatshorttimestamp(const isc_time_t *t, char *buf, unsigned int len);
/*%<
 * Format the time 't' into the buffer 'buf' of length 'len',
 * using the format "yyyymmddhhmmsssss" useful for file timestamping.
 * If the text does not fit in the buffer, the result is indeterminate,
 * but is always guaranteed to be null terminated.
 *
 *  Requires:
 *\li      'len' > 0
 *\li      'buf' points to an array of at least len chars
 *
 */

ISC_LANG_ENDDECLS
