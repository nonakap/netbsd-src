/*	$NetBSD: rdata_test.c,v 1.5 2025/05/21 14:48:06 christos Exp $	*/

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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING

#include <cmocka.h>
#include <openssl_shim.h>

#include <openssl/err.h>

#include <isc/commandline.h>
#include <isc/hex.h>
#include <isc/lex.h>
#include <isc/stdio.h>
#include <isc/types.h>
#include <isc/util.h>

#include <dns/rdata.h>

#include <tests/dns.h>

/*
 * An array of these structures is passed to compare_ok().
 */
struct compare_ok {
	const char *text1; /* text passed to fromtext_*() */
	const char *text2; /* text passed to fromtext_*() */
	int answer;	   /* -1, 0, 1 */
	int lineno;	   /* source line defining this RDATA */
};
typedef struct compare_ok compare_ok_t;

struct textvsunknown {
	const char *text1;
	const char *text2;
};
typedef struct textvsunknown textvsunknown_t;

/*
 * An array of these structures is passed to check_text_ok().
 */
typedef struct text_ok {
	const char *text_in;  /* text passed to fromtext_*() */
	const char *text_out; /* text expected from totext_*();
			       * NULL indicates text_in is invalid */
	unsigned int loop;
} text_ok_t;

/*
 * An array of these structures is passed to check_wire_ok().
 */
typedef struct wire_ok {
	unsigned char data[512]; /* RDATA in wire format */
	size_t len;		 /* octets of data to parse */
	bool ok;		 /* is this RDATA valid? */
	unsigned int loop;
} wire_ok_t;

#define COMPARE(r1, r2, answer) { r1, r2, answer, __LINE__ }
#define COMPARE_SENTINEL()	{ NULL, NULL, 0, __LINE__ }

#define TEXT_VALID_CHANGED(data_in, data_out)	    { data_in, data_out, 0 }
#define TEXT_VALID(data)			    { data, data, 0 }
#define TEXT_VALID_LOOP(loop, data)		    { data, data, loop }
#define TEXT_VALID_LOOPCHG(loop, data_in, data_out) { data_in, data_out, loop }
#define TEXT_INVALID(data)			    { data, NULL, 0 }
#define TEXT_SENTINEL()				    TEXT_INVALID(NULL)

#define VARGC(...) (sizeof((unsigned char[]){ __VA_ARGS__ }))
#define WIRE_TEST(ok, loop, ...) \
	{ { __VA_ARGS__ }, VARGC(__VA_ARGS__), ok, loop }
#define WIRE_VALID(...)		   WIRE_TEST(true, 0, __VA_ARGS__)
#define WIRE_VALID_LOOP(loop, ...) WIRE_TEST(true, loop, __VA_ARGS__)
/*
 * WIRE_INVALID() test cases must always have at least one octet specified to
 * distinguish them from WIRE_SENTINEL().  Use the 'empty_ok' parameter passed
 * to check_wire_ok() for indicating whether empty RDATA is allowed for a given
 * RR type or not.
 */
#define WIRE_INVALID(FIRST, ...) WIRE_TEST(false, 0, FIRST, __VA_ARGS__)
#define WIRE_SENTINEL()		 WIRE_TEST(false, 0)

static void
detect_uncleared_libcrypto_error(void) {
	const char *file, *func, *data;
	int line, flags;
	long err;
	bool leak = false;
	while ((err = ERR_get_error_all(&file, &line, &func, &data, &flags)) !=
	       0L)
	{
		fprintf(stderr,
			"# Uncleared libcrypto error: %s:%d %s %s %ld %x\n",
			file, line, func, data, err, flags);
		leak = true;
	}
	assert_false(leak);
}

/*
 * Call dns_rdata_fromwire() for data in 'src', which is 'srclen' octets in
 * size and represents RDATA of given 'type' and 'class'.  Store the resulting
 * uncompressed wire form in 'dst', which is 'dstlen' octets in size, and make
 * 'rdata' refer to that uncompressed wire form.
 */
static isc_result_t
wire_to_rdata(const unsigned char *src, size_t srclen, dns_rdataclass_t rdclass,
	      dns_rdatatype_t type, unsigned char *dst, size_t dstlen,
	      dns_rdata_t *rdata) {
	isc_buffer_t source, target;
	isc_result_t result;

	/*
	 * Set up len-octet buffer pointing at data.
	 */
	isc_buffer_constinit(&source, src, srclen);
	isc_buffer_add(&source, srclen);
	isc_buffer_setactive(&source, srclen);

	/*
	 * Initialize target buffer.
	 */
	isc_buffer_init(&target, dst, dstlen);

	/*
	 * Try converting input data into uncompressed wire form.
	 */
	result = dns_rdata_fromwire(rdata, rdclass, type, &source,
				    DNS_DECOMPRESS_ALWAYS, &target);
	detect_uncleared_libcrypto_error();

	return result;
}

/*
 * Call dns_rdata_towire() for rdata and write to result to dst.
 */
static isc_result_t
rdata_towire(dns_rdata_t *rdata, unsigned char *dst, size_t dstlen,
	     size_t *length) {
	isc_buffer_t target;
	dns_compress_t cctx;
	isc_result_t result;

	/*
	 * Initialize target buffer.
	 */
	isc_buffer_init(&target, dst, dstlen);

	/*
	 * Try converting input data into uncompressed wire form.
	 */
	dns_compress_init(&cctx, mctx, 0);
	result = dns_rdata_towire(rdata, &cctx, &target);
	detect_uncleared_libcrypto_error();
	dns_compress_invalidate(&cctx);

	*length = isc_buffer_usedlength(&target);

	return result;
}

static isc_result_t
additionaldata_cb(void *arg, const dns_name_t *name, dns_rdatatype_t qtype,
		  dns_rdataset_t *found DNS__DB_FLARG) {
	UNUSED(arg);
	UNUSED(name);
	UNUSED(qtype);
	UNUSED(found);
	return ISC_R_SUCCESS;
}

/*
 * call dns_rdata_additionaldata() for rdata.
 */
static isc_result_t
rdata_additionadata(dns_rdata_t *rdata) {
	return dns_rdata_additionaldata(rdata, dns_rootname, additionaldata_cb,
					NULL);
}

/*
 * Call dns_rdata_checknames() with various owner names chosen to
 * match well known forms.
 *
 * We are currently only checking that the calls do not trigger
 * assertion failures.
 *
 * XXXMPA A future extension could be to record the expected
 * result and the expected value of 'bad'.
 */
static void
rdata_checknames(dns_rdata_t *rdata) {
	dns_fixedname_t fixed, bfixed;
	dns_name_t *name, *bad;
	isc_result_t result;

	name = dns_fixedname_initname(&fixed);
	bad = dns_fixedname_initname(&bfixed);

	(void)dns_rdata_checknames(rdata, dns_rootname, NULL);
	(void)dns_rdata_checknames(rdata, dns_rootname, bad);

	result = dns_name_fromstring(name, "example.net", dns_rootname, 0,
				     NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	(void)dns_rdata_checknames(rdata, name, NULL);
	(void)dns_rdata_checknames(rdata, name, bad);

	result = dns_name_fromstring(name, "in-addr.arpa", dns_rootname, 0,
				     NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	(void)dns_rdata_checknames(rdata, name, NULL);
	(void)dns_rdata_checknames(rdata, name, bad);

	result = dns_name_fromstring(name, "ip6.arpa", dns_rootname, 0, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);
	(void)dns_rdata_checknames(rdata, name, NULL);
	(void)dns_rdata_checknames(rdata, name, bad);
}

/*
 * Test whether converting rdata to a type-specific struct and then back to
 * rdata results in the same uncompressed wire form.  This checks whether
 * tostruct_*() and fromstruct_*() routines for given RR class and type behave
 * consistently.
 *
 * This function is called for every correctly processed input RDATA, from both
 * check_text_ok_single() and check_wire_ok_single().
 */
static void
check_struct_conversions(dns_rdata_t *rdata, size_t structsize,
			 unsigned int loop) {
	dns_rdataclass_t rdclass = rdata->rdclass;
	dns_rdatatype_t type = rdata->type;
	isc_result_t result;
	isc_buffer_t target;
	void *rdata_struct;
	char buf[1024];
	unsigned int count = 0;

	rdata_struct = isc_mem_allocate(mctx, structsize);
	assert_non_null(rdata_struct);

	/*
	 * Convert from uncompressed wire form into type-specific struct.
	 */
	result = dns_rdata_tostruct(rdata, rdata_struct, NULL);
	detect_uncleared_libcrypto_error();
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Convert from type-specific struct into uncompressed wire form.
	 */
	isc_buffer_init(&target, buf, sizeof(buf));
	result = dns_rdata_fromstruct(NULL, rdclass, type, rdata_struct,
				      &target);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Ensure results are consistent.
	 */
	assert_int_equal(isc_buffer_usedlength(&target), rdata->length);

	assert_memory_equal(buf, rdata->data, rdata->length);

	/*
	 * Check that one can walk hip rendezvous servers and
	 * https/svcb parameters.
	 */
	switch (type) {
	case dns_rdatatype_hip: {
		dns_rdata_hip_t *hip = rdata_struct;

		for (result = dns_rdata_hip_first(hip); result == ISC_R_SUCCESS;
		     result = dns_rdata_hip_next(hip))
		{
			dns_name_t name;
			dns_name_init(&name, NULL);
			dns_rdata_hip_current(hip, &name);
			assert_int_not_equal(dns_name_countlabels(&name), 0);
			assert_true(dns_name_isabsolute(&name));
			count++;
		}
		assert_int_equal(result, ISC_R_NOMORE);
		assert_int_equal(count, loop);
		break;
	}
	case dns_rdatatype_https: {
		dns_rdata_in_https_t *https = rdata_struct;

		for (result = dns_rdata_in_https_first(https);
		     result == ISC_R_SUCCESS;
		     result = dns_rdata_in_https_next(https))
		{
			isc_region_t region;
			dns_rdata_in_https_current(https, &region);
			assert_true(region.length >= 4);
			count++;
		}
		assert_int_equal(result, ISC_R_NOMORE);
		assert_int_equal(count, loop);
		break;
	}
	case dns_rdatatype_svcb: {
		dns_rdata_in_svcb_t *svcb = rdata_struct;

		for (result = dns_rdata_in_svcb_first(svcb);
		     result == ISC_R_SUCCESS;
		     result = dns_rdata_in_svcb_next(svcb))
		{
			isc_region_t region;
			dns_rdata_in_svcb_current(svcb, &region);
			assert_true(region.length >= 4);
			count++;
		}
		assert_int_equal(result, ISC_R_NOMORE);
		assert_int_equal(count, loop);
		break;
	}
	}

	isc_mem_free(mctx, rdata_struct);
}

/*
 * Check whether converting supplied text form RDATA into uncompressed wire
 * form succeeds (tests fromtext_*()).  If so, try converting it back into text
 * form and see if it results in the original text (tests totext_*()).
 */
static void
check_text_ok_single(const text_ok_t *text_ok, dns_rdataclass_t rdclass,
		     dns_rdatatype_t type, size_t structsize) {
	unsigned char buf_fromtext[1024], buf_fromwire[1024], buf_towire[1024];
	dns_rdata_t rdata = DNS_RDATA_INIT, rdata2 = DNS_RDATA_INIT;
	char buf_totext[1024] = { 0 };
	isc_buffer_t target;
	isc_result_t result;
	size_t length = 0;

	if (debug) {
		fprintf(stdout, "#check_text_ok_single(%s)\n",
			text_ok->text_in);
	}
	/*
	 * Try converting text form RDATA into uncompressed wire form.
	 */
	result = dns_test_rdatafromstring(&rdata, rdclass, type, buf_fromtext,
					  sizeof(buf_fromtext),
					  text_ok->text_in, false);
	/*
	 * Check whether result is as expected.
	 */
	if (text_ok->text_out != NULL) {
		if (debug && result != ISC_R_SUCCESS) {
			fprintf(stdout, "# '%s'\n", text_ok->text_in);
			fprintf(stdout, "# result=%s\n",
				isc_result_totext(result));
		}
		assert_int_equal(result, ISC_R_SUCCESS);
	} else {
		if (debug && result == ISC_R_SUCCESS) {
			fprintf(stdout, "#'%s'\n", text_ok->text_in);
		}
		assert_int_not_equal(result, ISC_R_SUCCESS);
	}

	/*
	 * If text form RDATA was not parsed correctly, performing any
	 * additional checks is pointless.
	 */
	if (result != ISC_R_SUCCESS) {
		return;
	}

	/*
	 * Try converting uncompressed wire form RDATA back into text form and
	 * check whether the resulting text is the same as the original one.
	 */
	isc_buffer_init(&target, buf_totext, sizeof(buf_totext));
	result = dns_rdata_totext(&rdata, NULL, &target);
	detect_uncleared_libcrypto_error();
	if (result != ISC_R_SUCCESS && debug) {
		size_t i;
		fprintf(stdout, "# dns_rdata_totext -> %s",
			isc_result_totext(result));
		for (i = 0; i < rdata.length; i++) {
			if ((i % 16) == 0) {
				fprintf(stdout, "\n#");
			}
			fprintf(stdout, " %02x", rdata.data[i]);
		}
		fprintf(stdout, "\n");
	}
	assert_int_equal(result, ISC_R_SUCCESS);
	/*
	 * Ensure buf_totext is properly NUL terminated as dns_rdata_totext()
	 * may attempt different output formats writing into the apparently
	 * unused part of the buffer.
	 */
	isc_buffer_putuint8(&target, 0);
	if (debug && strcmp(buf_totext, text_ok->text_out) != 0) {
		fprintf(stdout, "# '%s' != '%s'\n", buf_totext,
			text_ok->text_out);
	}
	assert_string_equal(buf_totext, text_ok->text_out);

	if (debug) {
		fprintf(stdout, "#dns_rdata_totext -> '%s'\n", buf_totext);
	}

	/*
	 * Ensure that fromtext_*() output is valid input for fromwire_*().
	 */
	result = wire_to_rdata(rdata.data, rdata.length, rdclass, type,
			       buf_fromwire, sizeof(buf_fromwire), &rdata2);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(rdata.length, rdata2.length);
	assert_memory_equal(rdata.data, buf_fromwire, rdata.length);

	/*
	 * Ensure that fromtext_*() output is valid input for towire_*().
	 */
	result = rdata_towire(&rdata, buf_towire, sizeof(buf_towire), &length);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(rdata.length, length);
	assert_memory_equal(rdata.data, buf_towire, length);

	/*
	 * Test that additionaldata_*() succeeded.
	 */
	result = rdata_additionadata(&rdata);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Exercise checknames_*().
	 */
	rdata_checknames(&rdata);

	/*
	 * Perform two-way conversion checks between uncompressed wire form and
	 * type-specific struct.
	 */
	check_struct_conversions(&rdata, structsize, text_ok->loop);
}

/*
 * Test whether converting rdata to text form and then parsing the result of
 * that conversion again results in the same uncompressed wire form.  This
 * checks whether totext_*() output is parsable by fromtext_*() for given RR
 * class and type.
 *
 * This function is called for every input RDATA which is successfully parsed
 * by check_wire_ok_single() and whose type is not a meta-type.
 */
static void
check_text_conversions(dns_rdata_t *rdata) {
	char buf_totext[1024] = { 0 };
	unsigned char buf_fromtext[1024];
	isc_result_t result;
	isc_buffer_t target;
	dns_rdata_t rdata2 = DNS_RDATA_INIT;

	/*
	 * Convert uncompressed wire form RDATA into text form.  This
	 * conversion must succeed since input RDATA was successfully
	 * parsed by check_wire_ok_single().
	 */
	isc_buffer_init(&target, buf_totext, sizeof(buf_totext));
	result = dns_rdata_totext(rdata, NULL, &target);
	detect_uncleared_libcrypto_error();
	assert_int_equal(result, ISC_R_SUCCESS);
	/*
	 * Ensure buf_totext is properly NUL terminated as dns_rdata_totext()
	 * may attempt different output formats writing into the apparently
	 * unused part of the buffer.
	 */
	isc_buffer_putuint8(&target, 0);
	if (debug) {
		fprintf(stdout, "#'%s'\n", buf_totext);
	}

	/*
	 * Try parsing text form RDATA output by dns_rdata_totext() again.
	 */
	result = dns_test_rdatafromstring(&rdata2, rdata->rdclass, rdata->type,
					  buf_fromtext, sizeof(buf_fromtext),
					  buf_totext, false);
	if (debug && result != ISC_R_SUCCESS) {
		fprintf(stdout, "# result = %s\n", isc_result_totext(result));
		fprintf(stdout, "# '%s'\n", buf_fromtext);
	}
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(rdata2.length, rdata->length);
	assert_memory_equal(buf_fromtext, rdata->data, rdata->length);
}

/*
 * Test whether converting rdata to multi-line text form and then parsing the
 * result of that conversion again results in the same uncompressed wire form.
 * This checks whether multi-line totext_*() output is parsable by fromtext_*()
 * for given RR class and type.
 *
 * This function is called for every input RDATA which is successfully parsed
 * by check_wire_ok_single() and whose type is not a meta-type.
 */
static void
check_multiline_text_conversions(dns_rdata_t *rdata) {
	char buf_totext[1024] = { 0 };
	unsigned char buf_fromtext[1024];
	isc_result_t result;
	isc_buffer_t target;
	dns_rdata_t rdata2 = DNS_RDATA_INIT;
	unsigned int flags;

	/*
	 * Convert uncompressed wire form RDATA into multi-line text form.
	 * This conversion must succeed since input RDATA was successfully
	 * parsed by check_wire_ok_single().
	 */
	isc_buffer_init(&target, buf_totext, sizeof(buf_totext));
	flags = dns_master_styleflags(&dns_master_style_default);
	result = dns_rdata_tofmttext(rdata, dns_rootname, flags, 80 - 32, 4,
				     "\n", &target);
	detect_uncleared_libcrypto_error();
	assert_int_equal(result, ISC_R_SUCCESS);
	/*
	 * Ensure buf_totext is properly NUL terminated as
	 * dns_rdata_tofmttext() may attempt different output formats
	 * writing into the apparently unused part of the buffer.
	 */
	isc_buffer_putuint8(&target, 0);
	if (debug) {
		fprintf(stdout, "#'%s'\n", buf_totext);
	}

	/*
	 * Try parsing multi-line text form RDATA output by
	 * dns_rdata_tofmttext() again.
	 */
	result = dns_test_rdatafromstring(&rdata2, rdata->rdclass, rdata->type,
					  buf_fromtext, sizeof(buf_fromtext),
					  buf_totext, false);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(rdata2.length, rdata->length);
	assert_memory_equal(buf_fromtext, rdata->data, rdata->length);
}

/*
 * Test whether supplied wire form RDATA is properly handled as being either
 * valid or invalid for an RR of given rdclass and type.
 */
static void
check_wire_ok_single(const wire_ok_t *wire_ok, dns_rdataclass_t rdclass,
		     dns_rdatatype_t type, size_t structsize) {
	unsigned char buf[1024], buf_towire[1024];
	isc_result_t result;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	size_t length = 0;

	/*
	 * Try converting wire data into uncompressed wire form.
	 */
	result = wire_to_rdata(wire_ok->data, wire_ok->len, rdclass, type, buf,
			       sizeof(buf), &rdata);
	/*
	 * Check whether result is as expected.
	 */
	if (wire_ok->ok) {
		assert_int_equal(result, ISC_R_SUCCESS);
	} else {
		assert_int_not_equal(result, ISC_R_SUCCESS);
	}

	if (result != ISC_R_SUCCESS) {
		return;
	}

	/*
	 * If data was parsed correctly, perform two-way conversion checks
	 * between uncompressed wire form and type-specific struct.
	 *
	 * If the RR type is not a meta-type, additionally perform two-way
	 * conversion checks between:
	 *
	 *   - uncompressed wire form and text form,
	 *   - uncompressed wire form and multi-line text form.
	 */
	check_struct_conversions(&rdata, structsize, wire_ok->loop);
	if (!dns_rdatatype_ismeta(rdata.type)) {
		check_text_conversions(&rdata);
		check_multiline_text_conversions(&rdata);
	}

	/*
	 * Ensure that fromwire_*() output is valid input for towire_*().
	 */
	result = rdata_towire(&rdata, buf_towire, sizeof(buf_towire), &length);
	assert_int_equal(result, ISC_R_SUCCESS);
	assert_int_equal(rdata.length, length);
	assert_memory_equal(rdata.data, buf_towire, length);

	/*
	 * Test that additionaldata_*() succeeded.
	 */
	result = rdata_additionadata(&rdata);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Exercise checknames_*().
	 */
	rdata_checknames(&rdata);
}

/*
 * Test fromtext_*() and totext_*() routines for given RR class and type for
 * each text form RDATA in the supplied array.  See the comment for
 * check_text_ok_single() for an explanation of how exactly these routines are
 * tested.
 */
static void
check_text_ok(const text_ok_t *text_ok, dns_rdataclass_t rdclass,
	      dns_rdatatype_t type, size_t structsize) {
	size_t i;

	/*
	 * Check all entries in the supplied array.
	 */
	for (i = 0; text_ok[i].text_in != NULL; i++) {
		check_text_ok_single(&text_ok[i], rdclass, type, structsize);
	}
}

/*
 * For each wire form RDATA in the supplied array, check whether it is properly
 * handled as being either valid or invalid for an RR of given rdclass and
 * type, then check whether trying to process a zero-length wire data buffer
 * yields the expected result.  This checks whether the fromwire_*() routine
 * for given RR class and type behaves as expected.
 */
static void
check_wire_ok(const wire_ok_t *wire_ok, bool empty_ok, dns_rdataclass_t rdclass,
	      dns_rdatatype_t type, size_t structsize) {
	wire_ok_t empty_wire = WIRE_TEST(empty_ok, 0);
	size_t i;

	/*
	 * Check all entries in the supplied array.
	 */
	for (i = 0; wire_ok[i].len != 0; i++) {
		if (debug) {
			fprintf(stderr, "calling check_wire_ok_single on %zu\n",
				i);
		}
		check_wire_ok_single(&wire_ok[i], rdclass, type, structsize);
	}

	/*
	 * Check empty wire data.
	 */
	check_wire_ok_single(&empty_wire, rdclass, type, structsize);
}

/*
 * Check that two records compare as expected with dns_rdata_compare().
 */
static void
check_compare_ok_single(const compare_ok_t *compare_ok,
			dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	dns_rdata_t rdata1 = DNS_RDATA_INIT, rdata2 = DNS_RDATA_INIT;
	unsigned char buf1[1024], buf2[1024];
	isc_result_t result;
	int answer;

	result = dns_test_rdatafromstring(&rdata1, rdclass, type, buf1,
					  sizeof(buf1), compare_ok->text1,
					  false);
	if (result != ISC_R_SUCCESS) {
		fail_msg("# line %d: '%s': expected success, got failure",
			 compare_ok->lineno, compare_ok->text1);
	}

	result = dns_test_rdatafromstring(&rdata2, rdclass, type, buf2,
					  sizeof(buf2), compare_ok->text2,
					  false);

	if (result != ISC_R_SUCCESS) {
		fail_msg("# line %d: '%s': expected success, got failure",
			 compare_ok->lineno, compare_ok->text2);
	}

	answer = dns_rdata_compare(&rdata1, &rdata2);
	detect_uncleared_libcrypto_error();
	if (compare_ok->answer == 0 && answer != 0) {
		fail_msg("# line %d: dns_rdata_compare('%s', '%s'): "
			 "expected equal, got %s",
			 compare_ok->lineno, compare_ok->text1,
			 compare_ok->text2,
			 (answer > 0) ? "greater than" : "less than");
	}
	if (compare_ok->answer < 0 && answer >= 0) {
		fail_msg("# line %d: dns_rdata_compare('%s', '%s'): "
			 "expected less than, got %s",
			 compare_ok->lineno, compare_ok->text1,
			 compare_ok->text2,
			 (answer == 0) ? "equal" : "greater than");
	}
	if (compare_ok->answer > 0 && answer <= 0) {
		fail_msg("line %d: dns_rdata_compare('%s', '%s'): "
			 "expected greater than, got %s",
			 compare_ok->lineno, compare_ok->text1,
			 compare_ok->text2,
			 (answer == 0) ? "equal" : "less than");
	}
}

/*
 * Check that all the records sets in compare_ok compare as expected
 * with dns_rdata_compare().
 */
static void
check_compare_ok(const compare_ok_t *compare_ok, dns_rdataclass_t rdclass,
		 dns_rdatatype_t type) {
	size_t i;
	/*
	 * Check all entries in the supplied array.
	 */
	for (i = 0; compare_ok[i].text1 != NULL; i++) {
		check_compare_ok_single(&compare_ok[i], rdclass, type);
	}
}

/*
 * Test whether supplied sets of text form and/or wire form RDATA are handled
 * as expected.
 *
 * The empty_ok argument denotes whether an attempt to parse a zero-length wire
 * data buffer should succeed or not (it is valid for some RR types).  There is
 * no point in performing a similar check for empty text form RDATA, because
 * dns_rdata_fromtext() returns ISC_R_UNEXPECTEDEND before calling fromtext_*()
 * for the given RR class and type.
 */
static void
check_rdata(const text_ok_t *text_ok, const wire_ok_t *wire_ok,
	    const compare_ok_t *compare_ok, bool empty_ok,
	    dns_rdataclass_t rdclass, dns_rdatatype_t type, size_t structsize) {
	if (text_ok != NULL) {
		check_text_ok(text_ok, rdclass, type, structsize);
	}
	if (wire_ok != NULL) {
		check_wire_ok(wire_ok, empty_ok, rdclass, type, structsize);
	}
	if (compare_ok != NULL) {
		check_compare_ok(compare_ok, rdclass, type);
	}
}

/*
 * Check presentation vs unknown format of the record.
 */
static void
check_textvsunknown_single(const textvsunknown_t *textvsunknown,
			   dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	dns_rdata_t rdata1 = DNS_RDATA_INIT, rdata2 = DNS_RDATA_INIT;
	unsigned char buf1[1024], buf2[1024];
	isc_result_t result;

	result = dns_test_rdatafromstring(&rdata1, rdclass, type, buf1,
					  sizeof(buf1), textvsunknown->text1,
					  false);
	if (debug && result != ISC_R_SUCCESS) {
		fprintf(stdout, "# '%s'\n", textvsunknown->text1);
		fprintf(stdout, "# result=%s\n", isc_result_totext(result));
	}
	assert_int_equal(result, ISC_R_SUCCESS);
	result = dns_test_rdatafromstring(&rdata2, rdclass, type, buf2,
					  sizeof(buf2), textvsunknown->text2,
					  false);
	if (debug && result != ISC_R_SUCCESS) {
		fprintf(stdout, "# '%s'\n", textvsunknown->text2);
		fprintf(stdout, "# result=%s\n", isc_result_totext(result));
	}
	assert_int_equal(result, ISC_R_SUCCESS);
	if (debug && rdata1.length != rdata2.length) {
		fprintf(stdout, "# '%s'\n", textvsunknown->text1);
		fprintf(stdout, "# rdata1.length (%u) != rdata2.length (%u)\n",
			rdata1.length, rdata2.length);
	}
	assert_int_equal(rdata1.length, rdata2.length);
	if (debug && memcmp(rdata1.data, rdata2.data, rdata1.length) != 0) {
		unsigned int i;
		fprintf(stdout, "# '%s'\n", textvsunknown->text1);
		for (i = 0; i < rdata1.length; i++) {
			if (rdata1.data[i] != rdata2.data[i]) {
				fprintf(stderr, "# %u: %02x != %02x\n", i,
					rdata1.data[i], rdata2.data[i]);
			}
		}
	}
	assert_memory_equal(rdata1.data, rdata2.data, rdata1.length);
}

static void
check_textvsunknown(const textvsunknown_t *textvsunknown,
		    dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	size_t i;

	/*
	 * Check all entries in the supplied array.
	 */
	for (i = 0; textvsunknown[i].text1 != NULL; i++) {
		check_textvsunknown_single(&textvsunknown[i], rdclass, type);
	}
}

/*
 * Common tests for RR types based on KEY that require key data:
 *
 *   - CDNSKEY (RFC 7344)
 *   - DNSKEY (RFC 4034)
 *   - RKEY (draft-reid-dnsext-rkey-00)
 */
static void
key_required(void **state, dns_rdatatype_t type, size_t size) {
	wire_ok_t wire_ok[] = { /*
				 * RDATA must be at least 5 octets in size:
				 *
				 *   - 2 octets for Flags,
				 *   - 1 octet for Protocol,
				 *   - 1 octet for Algorithm,
				 *   - Public Key must not be empty.
				 *
				 * RFC 2535 section 3.1.2 allows the Public Key
				 * to be empty if bits 0-1 of Flags are both
				 * set, but that only applies to KEY records:
				 * for the RR types tested here, the Public Key
				 * must not be empty.
				 */
				WIRE_INVALID(0x00),
				WIRE_INVALID(0x00, 0x00),
				WIRE_INVALID(0x00, 0x00, 0x00),
				WIRE_INVALID(0xc0, 0x00, 0x00, 0x00),
				WIRE_INVALID(0x00, 0x00, 0x00, 0x00),
				WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x00),
				WIRE_SENTINEL()
	};

	UNUSED(state);

	check_rdata(NULL, wire_ok, NULL, false, dns_rdataclass_in, type, size);
}

/* APL RDATA manipulations */
ISC_RUN_TEST_IMPL(apl) {
	text_ok_t text_ok[] = {
		/* empty list */
		TEXT_VALID(""),
		/* min,max prefix IPv4 */
		TEXT_VALID("1:0.0.0.0/0"), TEXT_VALID("1:127.0.0.1/32"),
		/* min,max prefix IPv6 */
		TEXT_VALID("2:::/0"), TEXT_VALID("2:::1/128"),
		/* negated */
		TEXT_VALID("!1:0.0.0.0/0"), TEXT_VALID("!1:127.0.0.1/32"),
		TEXT_VALID("!2:::/0"), TEXT_VALID("!2:::1/128"),
		/* bits set after prefix length - not disallowed */
		TEXT_VALID("1:127.0.0.0/0"), TEXT_VALID("2:8000::/0"),
		/* multiple */
		TEXT_VALID("1:0.0.0.0/0 1:127.0.0.1/32"),
		TEXT_VALID("1:0.0.0.0/0 !1:127.0.0.1/32"),
		/* family 0, prefix 0, positive */
		TEXT_VALID("\\# 4 00000000"),
		/* family 0, prefix 0, negative */
		TEXT_VALID("\\# 4 00000080"),
		/* prefix too long */
		TEXT_INVALID("1:0.0.0.0/33"), TEXT_INVALID("2:::/129"),
		/*
		 * Sentinel.
		 */
		TEXT_SENTINEL()
	};
	wire_ok_t wire_ok[] = { /* zero length */
				WIRE_VALID(),
				/* prefix too big IPv4 */
				WIRE_INVALID(0x00, 0x01, 33U, 0x00),
				/* prefix too big IPv6 */
				WIRE_INVALID(0x00, 0x02, 129U, 0x00),
				/* trailing zero octet in afdpart */
				WIRE_INVALID(0x00, 0x00, 0x00, 0x01, 0x00),
				/*
				 * Sentinel.
				 */
				WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, true, dns_rdataclass_in,
		    dns_rdatatype_apl, sizeof(dns_rdata_in_apl_t));
}

/*
 * http://broadband-forum.org/ftp/pub/approved-specs/af-saa-0069.000.pdf
 *
 * ATMA RR’s have the following RDATA format:
 *
 *                                           1  1  1  1  1  1
 *             0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *          |          FORMAT       |                       |
 *          +--+--+--+--+--+--+--+--+                       |
 *          /                    ADDRESS                    /
 *          |                                               |
 *          +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The fields have the following meaning:
 *
 * * FORMAT: One octet that indicates the format of ADDRESS. The two
 *   possible values for FORMAT are value 0 indicating ATM End System Address
 *   (AESA) format and value 1 indicating E.164 format.
 *
 * * ADDRESS: Variable length string of octets containing the ATM address of
 *   the node to which this RR pertains.
 *
 * When the format value is 0, indicating that the address is in AESA format,
 * the address is coded as described in ISO 8348/AD 2 using the preferred
 * binary encoding of the ISO NSAP format. When the format value is 1,
 * indicating that the address is in E.164 format, the Address/Number Digits
 * appear in the order in which they would be entered on a numeric keypad.
 * Digits are coded in IA5 characters with the leftmost bit of each digit set
 * to 0.  This ATM address appears in ATM End System Address Octets field (AESA
 * format) or the Address/Number Digits field (E.164 format) of the Called
 * party number information element [ATMUNI3.1]. Subaddress information is
 * intentionally not included because E.164 subaddress information is used for
 * routing.
 *
 * ATMA RRs cause no additional section processing.
 */
ISC_RUN_TEST_IMPL(atma) {
	text_ok_t text_ok[] = { TEXT_VALID("00"),
				TEXT_VALID_CHANGED("0.0", "00"),
				/*
				 * multiple consecutive periods
				 */
				TEXT_INVALID("0..0"),
				/*
				 * trailing period
				 */
				TEXT_INVALID("00."),
				/*
				 * leading period
				 */
				TEXT_INVALID(".00"),
				/*
				 * Not full octets.
				 */
				TEXT_INVALID("000"),
				/*
				 * E.164
				 */
				TEXT_VALID("+61200000000"),
				/*
				 * E.164 with periods
				 */
				TEXT_VALID_CHANGED("+61.2.0000.0000", "+6120000"
								      "0000"),
				/*
				 * E.164 with period at end
				 */
				TEXT_INVALID("+61200000000."),
				/*
				 * E.164 with multiple consecutive periods
				 */
				TEXT_INVALID("+612..00000000"),
				/*
				 * E.164 with period before the leading digit.
				 */
				TEXT_INVALID("+.61200000000"),
				/*
				 * Sentinel.
				 */
				TEXT_SENTINEL() };
	wire_ok_t wire_ok[] = {
		/*
		 * Too short.
		 */
		WIRE_INVALID(0x00), WIRE_INVALID(0x01),
		/*
		 * all digits
		 */
		WIRE_VALID(0x01, '6', '1', '2', '0', '0', '0'),
		/*
		 * non digit
		 */
		WIRE_INVALID(0x01, '+', '6', '1', '2', '0', '0', '0'),
		/*
		 * Sentinel.
		 */
		WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_atma, sizeof(dns_rdata_in_atma_t));
}

/* AMTRELAY RDATA manipulations */
ISC_RUN_TEST_IMPL(amtrelay) {
	text_ok_t text_ok[] = {
		TEXT_INVALID(""), TEXT_INVALID("0"), TEXT_INVALID("0 0"),
		/* gateway type 0 */
		TEXT_VALID("0 0 0"), TEXT_VALID("0 1 0"),
		TEXT_INVALID("0 2 0"),	 /* discovery out of range */
		TEXT_VALID("255 1 0"),	 /* max precedence */
		TEXT_INVALID("256 1 0"), /* precedence out of range */

		/* IPv4 gateway */
		TEXT_INVALID("0 0 1"), /* no address */
		TEXT_VALID("0 0 1 0.0.0.0"),
		TEXT_INVALID("0 0 1 0.0.0.0 x"), /* extra */
		TEXT_INVALID("0 0 1 0.0.0.0.0"), /* bad address */
		TEXT_INVALID("0 0 1 ::"),	 /* bad address */
		TEXT_INVALID("0 0 1 ."),	 /* bad address */

		/* IPv6 gateway */
		TEXT_INVALID("0 0 2"), /* no address */
		TEXT_VALID("0 0 2 ::"), TEXT_INVALID("0 0 2 :: xx"), /* extra */
		TEXT_INVALID("0 0 2 0.0.0.0"), /* bad address */
		TEXT_INVALID("0 0 2 ."),       /* bad address */

		/* hostname gateway */
		TEXT_INVALID("0 0 3"), /* no name */
		/* IPv4 is a valid name */
		TEXT_VALID_CHANGED("0 0 3 0.0.0.0", "0 0 3 0.0.0.0."),
		/* IPv6 is a valid name */
		TEXT_VALID_CHANGED("0 0 3 ::", "0 0 3 ::."),
		TEXT_VALID_CHANGED("0 0 3 example", "0 0 3 example."),
		TEXT_VALID("0 0 3 example."),
		TEXT_INVALID("0 0 3 example. x"), /* extra */

		/* unknown gateway */
		TEXT_VALID("\\# 2 0004"), TEXT_VALID("\\# 2 0084"),
		TEXT_VALID("\\# 2 007F"), TEXT_VALID("\\# 3 000400"),
		TEXT_VALID("\\# 3 008400"), TEXT_VALID("\\# 3 00FF00"),

		/*
		 * Sentinel.
		 */
		TEXT_SENTINEL()
	};
	wire_ok_t wire_ok[] = {
		WIRE_INVALID(0x00), WIRE_VALID(0x00, 0x00),
		WIRE_VALID(0x00, 0x80), WIRE_INVALID(0x00, 0x00, 0x00),
		WIRE_INVALID(0x00, 0x80, 0x00),

		WIRE_INVALID(0x00, 0x01), WIRE_INVALID(0x00, 0x01, 0x00),
		WIRE_INVALID(0x00, 0x01, 0x00, 0x00),
		WIRE_INVALID(0x00, 0x01, 0x00, 0x00, 0x00),
		WIRE_VALID(0x00, 0x01, 0x00, 0x00, 0x00, 0x00),
		WIRE_INVALID(0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00),

		WIRE_INVALID(0x00, 0x02), WIRE_INVALID(0x00, 0x02, 0x00),
		WIRE_VALID(0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
			   0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14,
			   0x15),
		WIRE_INVALID(0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			     0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
			     0x14, 0x15, 0x16),

		WIRE_INVALID(0x00, 0x03), WIRE_VALID(0x00, 0x03, 0x00),
		WIRE_INVALID(0x00, 0x03, 0x00, 0x00), /* extra */

		WIRE_VALID(0x00, 0x04), WIRE_VALID(0x00, 0x04, 0x00),
		/*
		 * Sentinel.
		 */
		WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_amtrelay, sizeof(dns_rdata_amtrelay_t));
}

ISC_RUN_TEST_IMPL(cdnskey) {
	key_required(state, dns_rdatatype_cdnskey, sizeof(dns_rdata_cdnskey_t));
}

/*
 * CSYNC tests.
 *
 * RFC 7477:
 *
 * 2.1.  The CSYNC Resource Record Format
 *
 * 2.1.1.  The CSYNC Resource Record Wire Format
 *
 *    The CSYNC RDATA consists of the following fields:
 *
 *                           1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                          SOA Serial                           |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |       Flags                   |            Type Bit Map       /
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      /                     Type Bit Map (continued)                  /
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 2.1.1.1.  The SOA Serial Field
 *
 *    The SOA Serial field contains a copy of the 32-bit SOA serial number
 *    from the child zone.  If the soaminimum flag is set, parental agents
 *    querying children's authoritative servers MUST NOT act on data from
 *    zones advertising an SOA serial number less than this value.  See
 *    [RFC1982] for properly implementing "less than" logic.  If the
 *    soaminimum flag is not set, parental agents MUST ignore the value in
 *    the SOA Serial field.  Clients can set the field to any value if the
 *    soaminimum flag is unset, such as the number zero.
 *
 * (...)
 *
 * 2.1.1.2.  The Flags Field
 *
 *    The Flags field contains 16 bits of boolean flags that define
 *    operations that affect the processing of the CSYNC record.  The flags
 *    defined in this document are as follows:
 *
 *       0x00 0x01: "immediate"
 *
 *       0x00 0x02: "soaminimum"
 *
 *    The definitions for how the flags are to be used can be found in
 *    Section 3.
 *
 *    The remaining flags are reserved for use by future specifications.
 *    Undefined flags MUST be set to 0 by CSYNC publishers.  Parental
 *    agents MUST NOT process a CSYNC record if it contains a 1 value for a
 *    flag that is unknown to or unsupported by the parental agent.
 *
 * 2.1.1.2.1.  The Type Bit Map Field
 *
 *    The Type Bit Map field indicates the record types to be processed by
 *    the parental agent, according to the procedures in Section 3.  The
 *    Type Bit Map field is encoded in the same way as the Type Bit Map
 *    field of the NSEC record, described in [RFC4034], Section 4.1.2.  If
 *    a bit has been set that a parental agent implementation does not
 *    understand, the parental agent MUST NOT act upon the record.
 *    Specifically, a parental agent must not simply copy the data, and it
 *    must understand the semantics associated with a bit in the Type Bit
 *    Map field that has been set to 1.
 */
ISC_RUN_TEST_IMPL(csync) {
	text_ok_t text_ok[] = { TEXT_INVALID(""),
				TEXT_INVALID("0"),
				TEXT_VALID("0 0"),
				TEXT_VALID("0 0 A"),
				TEXT_VALID("0 0 NS"),
				TEXT_VALID("0 0 AAAA"),
				TEXT_VALID("0 0 A AAAA"),
				TEXT_VALID("0 0 A NS AAAA"),
				TEXT_INVALID("0 0 A NS AAAA BOGUS"),
				TEXT_SENTINEL() };
	wire_ok_t wire_ok[] = {
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Serial + flags only.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Bad type map.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Bad type map.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Good type map.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			   0x02),
		/*
		 * Sentinel.
		 */
		WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_csync, sizeof(dns_rdata_csync_t));
}

ISC_RUN_TEST_IMPL(dnskey) {
	key_required(state, dns_rdatatype_dnskey, sizeof(dns_rdata_dnskey_t));
}

/*
 * DOA tests.
 *
 * draft-durand-doa-over-dns-03:
 *
 * 3.2.  DOA RDATA Wire Format
 *
 *        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *     0: |                                                               |
 *        |                        DOA-ENTERPRISE                         |
 *        |                                                               |
 *        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *     4: |                                                               |
 *        |                           DOA-TYPE                            |
 *        |                                                               |
 *        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *     8: |         DOA-LOCATION          |         DOA-MEDIA-TYPE        /
 *        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    10: /                                                               /
 *        /                  DOA-MEDIA-TYPE (continued)                   /
 *        /                                                               /
 *        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *        /                                                               /
 *        /                           DOA-DATA                            /
 *        /                                                               /
 *        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 *    DOA-ENTERPRISE: a 32-bit unsigned integer in network order.
 *
 *    DOA-TYPE: a 32-bit unsigned integer in network order.
 *
 *    DOA-LOCATION: an 8-bit unsigned integer.
 *
 *    DOA-MEDIA-TYPE: A <character-string> (see [RFC1035]).  The first
 *    octet of the <character-string> contains the number of characters to
 *    follow.
 *
 *    DOA-DATA: A variable length blob of binary data.  The length of the
 *    DOA-DATA is not contained within the wire format of the RR and has to
 *    be computed from the RDLENGTH of the entire RR once other fields have
 *    been taken into account.
 *
 * 3.3.  DOA RDATA Presentation Format
 *
 *    The DOA-ENTERPRISE field is presented as an unsigned 32-bit decimal
 *    integer with range 0 - 4,294,967,295.
 *
 *    The DOA-TYPE field is presented as an unsigned 32-bit decimal integer
 *    with range 0 - 4,294,967,295.
 *
 *    The DOA-LOCATION field is presented as an unsigned 8-bit decimal
 *    integer with range 0 - 255.
 *
 *    The DOA-MEDIA-TYPE field is presented as a single <character-string>.
 *
 *    The DOA-DATA is presented as Base64 encoded data [RFC4648] unless the
 *    DOA-DATA is empty in which case it is presented as a single dash
 *    character ("-", ASCII 45).  White space is permitted within Base64
 *    data.
 */
ISC_RUN_TEST_IMPL(doa) {
	text_ok_t text_ok[] = {
		/*
		 * Valid, non-empty DOA-DATA.
		 */
		TEXT_VALID("0 0 1 \"text/plain\" Zm9v"),
		/*
		 * Valid, non-empty DOA-DATA with whitespace in between.
		 */
		TEXT_VALID_CHANGED("0 0 1 \"text/plain\" Zm 9v", "0 0 1 "
								 "\"text/"
								 "plain\" "
								 "Zm9v"),
		/*
		 * Valid, unquoted DOA-MEDIA-TYPE, non-empty DOA-DATA.
		 */
		TEXT_VALID_CHANGED("0 0 1 text/plain Zm9v", "0 0 1 "
							    "\"text/plain\" "
							    "Zm9v"),
		/*
		 * Invalid, quoted non-empty DOA-DATA.
		 */
		TEXT_INVALID("0 0 1 \"text/plain\" \"Zm9v\""),
		/*
		 * Valid, empty DOA-DATA.
		 */
		TEXT_VALID("0 0 1 \"text/plain\" -"),
		/*
		 * Invalid, quoted empty DOA-DATA.
		 */
		TEXT_INVALID("0 0 1 \"text/plain\" \"-\""),
		/*
		 * Invalid, missing "-" in empty DOA-DATA.
		 */
		TEXT_INVALID("0 0 1 \"text/plain\""),
		/*
		 * Valid, undefined DOA-LOCATION.
		 */
		TEXT_VALID("0 0 100 \"text/plain\" Zm9v"),
		/*
		 * Invalid, DOA-LOCATION too big.
		 */
		TEXT_INVALID("0 0 256 \"text/plain\" ZM9v"),
		/*
		 * Valid, empty DOA-MEDIA-TYPE, non-empty DOA-DATA.
		 */
		TEXT_VALID("0 0 2 \"\" aHR0cHM6Ly93d3cuaXNjLm9yZy8="),
		/*
		 * Valid, empty DOA-MEDIA-TYPE, empty DOA-DATA.
		 */
		TEXT_VALID("0 0 1 \"\" -"),
		/*
		 * Valid, DOA-MEDIA-TYPE with a space.
		 */
		TEXT_VALID("0 0 1 \"plain text\" Zm9v"),
		/*
		 * Invalid, missing DOA-MEDIA-TYPE.
		 */
		TEXT_INVALID("1234567890 1234567890 1"),
		/*
		 * Valid, DOA-DATA over 255 octets.
		 */
		TEXT_VALID("1234567890 1234567890 1 \"image/gif\" "
			   "R0lGODlhKAAZAOMCAGZmZgBmmf///zOZzMz//5nM/zNmmWbM"
			   "/5nMzMzMzACZ/////////////////////yH5BAEKAA8ALAAA"
			   "AAAoABkAAATH8IFJK5U2a4337F5ogRkpnoCJrly7PrCKyh8c"
			   "3HgAhzT35MDbbtO7/IJIHbGiOiaTxVTpSVWWLqNq1UVyapNS"
			   "1wd3OAxug0LhnCubcVhsxysQnOt4ATpvvzHlFzl1AwODhWeF"
			   "AgRpen5/UhheAYMFdUB4SFcpGEGGdQeCAqBBLTuSk30EeXd9"
			   "pEsAbKGxjHqDSE0Sp6ixN4N1BJmbc7lIhmsBich1awPAjkY1"
			   "SZR8bJWrz382SGqIBQQFQd4IsUTaX+ceuudPEQA7"),
		/*
		 * Invalid, bad Base64 in DOA-DATA.
		 */
		TEXT_INVALID("1234567890 1234567890 1 \"image/gif\" R0lGODl"),
		/*
		 * Sentinel.
		 */
		TEXT_SENTINEL()
	};
	wire_ok_t wire_ok[] = {
		/*
		 * Valid, empty DOA-MEDIA-TYPE, empty DOA-DATA.
		 */
		WIRE_VALID(0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x01,
			   0x00),
		/*
		 * Invalid, missing DOA-MEDIA-TYPE.
		 */
		WIRE_INVALID(0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
			     0x01),
		/*
		 * Invalid, malformed DOA-MEDIA-TYPE length.
		 */
		WIRE_INVALID(0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78,
			     0x01, 0xff),
		/*
		 * Valid, empty DOA-DATA.
		 */
		WIRE_VALID(0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x01,
			   0x03, 0x66, 0x6f, 0x6f),
		/*
		 * Valid, non-empty DOA-DATA.
		 */
		WIRE_VALID(0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x01,
			   0x03, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72),
		/*
		 * Valid, DOA-DATA over 255 octets.
		 */
		WIRE_VALID(0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x01,
			   0x06, 0x62, 0x69, 0x6e, 0x61, 0x72, 0x79, 0x00, 0x66,
			   0x99, 0xff, 0xff, 0xff, 0x33, 0x99, 0xcc, 0xcc, 0xff,
			   0xff, 0x99, 0xcc, 0xff, 0x33, 0x66, 0x99, 0x66, 0xcc,
			   0xff, 0x99, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x00, 0x99,
			   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x21, 0xf9,
			   0x04, 0x01, 0x0a, 0x00, 0x0f, 0x00, 0x2c, 0x00, 0x00,
			   0x00, 0x00, 0x28, 0x00, 0x19, 0x00, 0x00, 0x04, 0xc7,
			   0xf0, 0x81, 0x49, 0x2b, 0x95, 0x36, 0x6b, 0x8d, 0xf7,
			   0xec, 0x5e, 0x68, 0x81, 0x19, 0x29, 0x9e, 0x80, 0x89,
			   0xae, 0x5c, 0xbb, 0x3e, 0xb0, 0x8a, 0xca, 0x1f, 0x1c,
			   0xdc, 0x78, 0x00, 0x87, 0x34, 0xf7, 0xe4, 0xc0, 0xdb,
			   0x6e, 0xd3, 0xbb, 0xfc, 0x82, 0x48, 0x1d, 0xb1, 0xa2,
			   0x3a, 0x26, 0x93, 0xc5, 0x54, 0xe9, 0x49, 0x55, 0x96,
			   0x2e, 0xa3, 0x6a, 0xd5, 0x45, 0x72, 0x6a, 0x93, 0x52,
			   0xd7, 0x07, 0x77, 0x38, 0x0c, 0x6e, 0x83, 0x42, 0xe1,
			   0x9c, 0x2b, 0x9b, 0x71, 0x58, 0x6c, 0xc7, 0x2b, 0x10,
			   0x9c, 0xeb, 0x78, 0x01, 0x3a, 0x6f, 0xbf, 0x31, 0xe5,
			   0x17, 0x39, 0x75, 0x03, 0x03, 0x83, 0x85, 0x67, 0x85,
			   0x02, 0x04, 0x69, 0x7a, 0x7e, 0x7f, 0x52, 0x18, 0x5e,
			   0x01, 0x83, 0x05, 0x75, 0x40, 0x78, 0x48, 0x57, 0x29,
			   0x18, 0x41, 0x86, 0x75, 0x07, 0x82, 0x02, 0xa0, 0x41,
			   0x2d, 0x3b, 0x92, 0x93, 0x7d, 0x04, 0x79, 0x77, 0x7d,
			   0xa4, 0x4b, 0x00, 0x6c, 0xa1, 0xb1, 0x8c, 0x7a, 0x83,
			   0x48, 0x4d, 0x12, 0xa7, 0xa8, 0xb1, 0x37, 0x83, 0x75,
			   0x04, 0x99, 0x9b, 0x73, 0xb9, 0x48, 0x86, 0x6b, 0x01,
			   0x89, 0xc8, 0x75, 0x6b, 0x03, 0xc0, 0x8e, 0x46, 0x35,
			   0x49, 0x94, 0x7c, 0x6c, 0x95, 0xab, 0xcf, 0x7f, 0x36,
			   0x48, 0x6a, 0x88, 0x05, 0x04, 0x05, 0x41, 0xde, 0x08,
			   0xb1, 0x44, 0xda, 0x5f, 0xe7, 0x1e, 0xba, 0xe7, 0x4f,
			   0x11, 0x00, 0x3b),
		/*
		 * Sentinel.
		 */
		WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_doa, sizeof(dns_rdata_doa_t));
}

/*
 * DS tests.
 *
 * RFC 4034:
 *
 * 5.1.  DS RDATA Wire Format
 *
 *    The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
 *    Algorithm field, a 1 octet Digest Type field, and a Digest field.
 *
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |           Key Tag             |  Algorithm    |  Digest Type  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    /                                                               /
 *    /                            Digest                             /
 *    /                                                               /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 5.1.1.  The Key Tag Field
 *
 *    The Key Tag field lists the key tag of the DNSKEY RR referred to by
 *    the DS record, in network byte order.
 *
 *    The Key Tag used by the DS RR is identical to the Key Tag used by
 *    RRSIG RRs.  Appendix B describes how to compute a Key Tag.
 *
 * 5.1.2.  The Algorithm Field
 *
 *    The Algorithm field lists the algorithm number of the DNSKEY RR
 *    referred to by the DS record.
 *
 *    The algorithm number used by the DS RR is identical to the algorithm
 *    number used by RRSIG and DNSKEY RRs.  Appendix A.1 lists the
 *    algorithm number types.
 *
 * 5.1.3.  The Digest Type Field
 *
 *    The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
 *    RR.  The Digest Type field identifies the algorithm used to construct
 *    the digest.  Appendix A.2 lists the possible digest algorithm types.
 *
 * 5.1.4.  The Digest Field
 *
 *    The DS record refers to a DNSKEY RR by including a digest of that
 *    DNSKEY RR.
 *
 *    The digest is calculated by concatenating the canonical form of the
 *    fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
 *    and then applying the digest algorithm.
 *
 *      digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
 *
 *       "|" denotes concatenation
 *
 *      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.
 *
 *    The size of the digest may vary depending on the digest algorithm and
 *    DNSKEY RR size.  As of the time of this writing, the only defined
 *    digest algorithm is SHA-1, which produces a 20 octet digest.
 */
ISC_RUN_TEST_IMPL(ds) {
	text_ok_t text_ok[] = {
		/*
		 * Invalid, empty record.
		 */
		TEXT_INVALID(""),
		/*
		 * Invalid, no algorithm.
		 */
		TEXT_INVALID("0"),
		/*
		 * Invalid, no digest type.
		 */
		TEXT_INVALID("0 0"),
		/*
		 * Invalid, no digest.
		 */
		TEXT_INVALID("0 0 0"),
		/*
		 * Valid, 1-octet digest for a reserved digest type.
		 */
		TEXT_VALID("0 0 0 00"),
		/*
		 * Invalid, short SHA-1 digest.
		 */
		TEXT_INVALID("0 0 1 00"),
		TEXT_INVALID("0 0 1 4FDCE83016EDD29077621FE568F8DADDB5809B"),
		/*
		 * Valid, 20-octet SHA-1 digest.
		 */
		TEXT_VALID("0 0 1 4FDCE83016EDD29077621FE568F8DADDB5809B6A"),
		/*
		 * Invalid, excessively long SHA-1 digest.
		 */
		TEXT_INVALID("0 0 1 4FDCE83016EDD29077621FE568F8DADDB5809B"
			     "6A00"),
		/*
		 * Invalid, short SHA-256 digest.
		 */
		TEXT_INVALID("0 0 2 00"),
		TEXT_INVALID("0 0 2 D001BD422FFDA9B745425B71DC17D007E69186"
			     "9BD59C5F237D9BF85434C313"),
		/*
		 * Valid, 32-octet SHA-256 digest.
		 */
		TEXT_VALID_CHANGED("0 0 2 "
				   "D001BD422FFDA9B745425B71DC17D007E691869B"
				   "D59C5F237D9BF85434C3133F",
				   "0 0 2 "
				   "D001BD422FFDA9B745425B71DC17D007E691869B"
				   "D59C5F237D9BF854 34C3133F"),
		/*
		 * Invalid, excessively long SHA-256 digest.
		 */
		TEXT_INVALID("0 0 2 D001BD422FFDA9B745425B71DC17D007E69186"
			     "9BD59C5F237D9BF85434C3133F00"),
		/*
		 * Valid, GOST is no longer supported, hence no length checks.
		 */
		TEXT_VALID("0 0 3 00"),
		/*
		 * Invalid, short SHA-384 digest.
		 */
		TEXT_INVALID("0 0 4 00"),
		TEXT_INVALID("0 0 4 AC748D6C5AA652904A8763D64B7DFFFFA98152"
			     "BE12128D238BEBB4814B648F5A841E15CAA2DE348891"
			     "A37A699F65E5"),
		/*
		 * Valid, 48-octet SHA-384 digest.
		 */
		TEXT_VALID_CHANGED("0 0 4 "
				   "AC748D6C5AA652904A8763D64B7DFFFFA98152BE"
				   "12128D238BEBB4814B648F5A841E15CAA2DE348891A"
				   "37A"
				   "699F65E54D",
				   "0 0 4 "
				   "AC748D6C5AA652904A8763D64B7DFFFFA98152BE"
				   "12128D238BEBB481 "
				   "4B648F5A841E15CAA2DE348891A37A"
				   "699F65E54D"),
		/*
		 * Invalid, excessively long SHA-384 digest.
		 */
		TEXT_INVALID("0 0 4 AC748D6C5AA652904A8763D64B7DFFFFA98152"
			     "BE12128D238BEBB4814B648F5A841E15CAA2DE348891"
			     "A37A699F65E54D00"),
		/*
		 * Valid, 1-octet digest for an unassigned digest type.
		 */
		TEXT_VALID("0 0 5 00"),
		/*
		 * Sentinel.
		 */
		TEXT_SENTINEL()
	};
	wire_ok_t wire_ok[] = {
		/*
		 * Invalid, truncated key tag.
		 */
		WIRE_INVALID(0x00),
		/*
		 * Invalid, no algorithm.
		 */
		WIRE_INVALID(0x00, 0x00),
		/*
		 * Invalid, no digest type.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00),
		/*
		 * Invalid, no digest.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00),
		/*
		 * Valid, 1-octet digest for a reserved digest type.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Invalid, short SHA-1 digest.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x01, 0x00),
		WIRE_INVALID(0x00, 0x00, 0x00, 0x01, 0x4F, 0xDC, 0xE8, 0x30,
			     0x16, 0xED, 0xD2, 0x90, 0x77, 0x62, 0x1F, 0xE5,
			     0x68, 0xF8, 0xDA, 0xDD, 0xB5, 0x80, 0x9B),
		/*
		 * Valid, 20-octet SHA-1 digest.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x01, 0x4F, 0xDC, 0xE8, 0x30, 0x16,
			   0xED, 0xD2, 0x90, 0x77, 0x62, 0x1F, 0xE5, 0x68, 0xF8,
			   0xDA, 0xDD, 0xB5, 0x80, 0x9B, 0x6A),
		/*
		 * Invalid, excessively long SHA-1 digest.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x01, 0x4F, 0xDC, 0xE8, 0x30,
			     0x16, 0xED, 0xD2, 0x90, 0x77, 0x62, 0x1F, 0xE5,
			     0x68, 0xF8, 0xDA, 0xDD, 0xB5, 0x80, 0x9B, 0x6A,
			     0x00),
		/*
		 * Invalid, short SHA-256 digest.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x02, 0x00),
		WIRE_INVALID(0x00, 0x00, 0x00, 0x02, 0xD0, 0x01, 0xBD, 0x42,
			     0x2F, 0xFD, 0xA9, 0xB7, 0x45, 0x42, 0x5B, 0x71,
			     0xDC, 0x17, 0xD0, 0x07, 0xE6, 0x91, 0x86, 0x9B,
			     0xD5, 0x9C, 0x5F, 0x23, 0x7D, 0x9B, 0xF8, 0x54,
			     0x34, 0xC3, 0x13),
		/*
		 * Valid, 32-octet SHA-256 digest.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x02, 0xD0, 0x01, 0xBD, 0x42, 0x2F,
			   0xFD, 0xA9, 0xB7, 0x45, 0x42, 0x5B, 0x71, 0xDC, 0x17,
			   0xD0, 0x07, 0xE6, 0x91, 0x86, 0x9B, 0xD5, 0x9C, 0x5F,
			   0x23, 0x7D, 0x9B, 0xF8, 0x54, 0x34, 0xC3, 0x13,
			   0x3F),
		/*
		 * Invalid, excessively long SHA-256 digest.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x02, 0xD0, 0x01, 0xBD, 0x42,
			     0x2F, 0xFD, 0xA9, 0xB7, 0x45, 0x42, 0x5B, 0x71,
			     0xDC, 0x17, 0xD0, 0x07, 0xE6, 0x91, 0x86, 0x9B,
			     0xD5, 0x9C, 0x5F, 0x23, 0x7D, 0x9B, 0xF8, 0x54,
			     0x34, 0xC3, 0x13, 0x3F, 0x00),
		/*
		 * Valid, GOST is no longer supported, hence no length checks.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x03, 0x00),
		/*
		 * Invalid, short SHA-384 digest.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x04, 0x00),
		WIRE_INVALID(0x00, 0x00, 0x00, 0x04, 0xAC, 0x74, 0x8D, 0x6C,
			     0x5A, 0xA6, 0x52, 0x90, 0x4A, 0x87, 0x63, 0xD6,
			     0x4B, 0x7D, 0xFF, 0xFF, 0xA9, 0x81, 0x52, 0xBE,
			     0x12, 0x12, 0x8D, 0x23, 0x8B, 0xEB, 0xB4, 0x81,
			     0x4B, 0x64, 0x8F, 0x5A, 0x84, 0x1E, 0x15, 0xCA,
			     0xA2, 0xDE, 0x34, 0x88, 0x91, 0xA3, 0x7A, 0x69,
			     0x9F, 0x65, 0xE5),
		/*
		 * Valid, 48-octet SHA-384 digest.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x04, 0xAC, 0x74, 0x8D, 0x6C, 0x5A,
			   0xA6, 0x52, 0x90, 0x4A, 0x87, 0x63, 0xD6, 0x4B, 0x7D,
			   0xFF, 0xFF, 0xA9, 0x81, 0x52, 0xBE, 0x12, 0x12, 0x8D,
			   0x23, 0x8B, 0xEB, 0xB4, 0x81, 0x4B, 0x64, 0x8F, 0x5A,
			   0x84, 0x1E, 0x15, 0xCA, 0xA2, 0xDE, 0x34, 0x88, 0x91,
			   0xA3, 0x7A, 0x69, 0x9F, 0x65, 0xE5, 0x4D),
		/*
		 * Invalid, excessively long SHA-384 digest.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x04, 0xAC, 0x74, 0x8D, 0x6C,
			     0x5A, 0xA6, 0x52, 0x90, 0x4A, 0x87, 0x63, 0xD6,
			     0x4B, 0x7D, 0xFF, 0xFF, 0xA9, 0x81, 0x52, 0xBE,
			     0x12, 0x12, 0x8D, 0x23, 0x8B, 0xEB, 0xB4, 0x81,
			     0x4B, 0x64, 0x8F, 0x5A, 0x84, 0x1E, 0x15, 0xCA,
			     0xA2, 0xDE, 0x34, 0x88, 0x91, 0xA3, 0x7A, 0x69,
			     0x9F, 0x65, 0xE5, 0x4D, 0x00),
		WIRE_VALID(0x00, 0x00, 0x04, 0x00, 0x00),
		/*
		 * Sentinel.
		 */
		WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_ds, sizeof(dns_rdata_ds_t));
}

/*
 * EDNS Client Subnet tests.
 *
 * RFC 7871:
 *
 * 6.  Option Format
 *
 *    This protocol uses an EDNS0 [RFC6891] option to include client
 *    address information in DNS messages.  The option is structured as
 *    follows:
 *
 *                 +0 (MSB)                            +1 (LSB)
 *       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    0: |                          OPTION-CODE                          |
 *       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    2: |                         OPTION-LENGTH                         |
 *       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    4: |                            FAMILY                             |
 *       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    6: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
 *       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    8: |                           ADDRESS...                          /
 *       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 *    o  (Defined in [RFC6891]) OPTION-CODE, 2 octets, for ECS is 8 (0x00
 *       0x08).
 *
 *    o  (Defined in [RFC6891]) OPTION-LENGTH, 2 octets, contains the
 *       length of the payload (everything after OPTION-LENGTH) in octets.
 *
 *    o  FAMILY, 2 octets, indicates the family of the address contained in
 *       the option, using address family codes as assigned by IANA in
 *       Address Family Numbers [Address_Family_Numbers].
 *
 *    The format of the address part depends on the value of FAMILY.  This
 *    document only defines the format for FAMILY 1 (IPv4) and FAMILY 2
 *    (IPv6), which are as follows:
 *
 *    o  SOURCE PREFIX-LENGTH, an unsigned octet representing the leftmost
 *       number of significant bits of ADDRESS to be used for the lookup.
 *       In responses, it mirrors the same value as in the queries.
 *
 *    o  SCOPE PREFIX-LENGTH, an unsigned octet representing the leftmost
 *       number of significant bits of ADDRESS that the response covers.
 *       In queries, it MUST be set to 0.
 *
 *    o  ADDRESS, variable number of octets, contains either an IPv4 or
 *       IPv6 address, depending on FAMILY, which MUST be truncated to the
 *       number of bits indicated by the SOURCE PREFIX-LENGTH field,
 *       padding with 0 bits to pad to the end of the last octet needed.
 *
 *    o  A server receiving an ECS option that uses either too few or too
 *       many ADDRESS octets, or that has non-zero ADDRESS bits set beyond
 *       SOURCE PREFIX-LENGTH, SHOULD return FORMERR to reject the packet,
 *       as a signal to the software developer making the request to fix
 *       their implementation.
 *
 *    All fields are in network byte order ("big-endian", per [RFC1700],
 *    Data Notation).
 */
ISC_RUN_TEST_IMPL(edns_client_subnet) {
	wire_ok_t wire_ok[] = {
		/*
		 * Option code with no content.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 0x00),
		/*
		 * Option code family 0, source 0, scope 0.
		 */
		WIRE_VALID(0x00, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Option code family 1 (IPv4), source 0, scope 0.
		 */
		WIRE_VALID(0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00),
		/*
		 * Option code family 2 (IPv6) , source 0, scope 0.
		 */
		WIRE_VALID(0x00, 0x08, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00),
		/*
		 * Extra octet.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
			     0x00),
		/*
		 * Source too long for IPv4.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 8, 0x00, 0x01, 33, 0x00, 0x00,
			     0x00, 0x00, 0x00),
		/*
		 * Source too long for IPv6.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 20, 0x00, 0x02, 129, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Scope too long for IPv4.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 8, 0x00, 0x01, 0x00, 33, 0x00,
			     0x00, 0x00, 0x00),
		/*
		 * Scope too long for IPv6.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 20, 0x00, 0x02, 0x00, 129, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * When family=0, source and scope should be 0.
		 */
		WIRE_VALID(0x00, 0x08, 0x00, 4, 0x00, 0x00, 0x00, 0x00),
		/*
		 * When family=0, source and scope should be 0.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 5, 0x00, 0x00, 0x01, 0x00, 0x00),
		/*
		 * When family=0, source and scope should be 0.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 5, 0x00, 0x00, 0x00, 0x01, 0x00),
		/*
		 * Length too short for source IPv4.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 7, 0x00, 0x01, 32, 0x00, 0x00,
			     0x00, 0x00),
		/*
		 * Length too short for source IPv6.
		 */
		WIRE_INVALID(0x00, 0x08, 0x00, 19, 0x00, 0x02, 128, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Sentinel.
		 */
		WIRE_SENTINEL()
	};

	check_rdata(NULL, wire_ok, NULL, true, dns_rdataclass_in,
		    dns_rdatatype_opt, sizeof(dns_rdata_opt_t));
}

/*
 * http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
 *
 * The RDATA portion of both the NIMLOC and EID records contains
 * uninterpreted binary data.  The representation in the text master file
 * is an even number of hex characters (0 to 9, a to f), case is not
 * significant.  For readability, whitespace may be included in the value
 * field and should be ignored when reading a master file.
 */
ISC_RUN_TEST_IMPL(eid) {
	text_ok_t text_ok[] = { TEXT_VALID("AABBCC"),
				TEXT_VALID_CHANGED("AA bb cc", "AABBCC"),
				TEXT_INVALID("aab"),
				/*
				 * Sentinel.
				 */
				TEXT_SENTINEL() };
	wire_ok_t wire_ok[] = { WIRE_VALID(0x00), WIRE_VALID(0xAA, 0xBB, 0xCC),
				/*
				 * Sentinel.
				 */
				WIRE_SENTINEL() };

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_eid, sizeof(dns_rdata_in_eid_t));
}

/*
 * test that an oversized HIP record will be rejected
 */
ISC_RUN_TEST_IMPL(hip) {
	text_ok_t text_ok[] = {
		/* RFC 8005 examples. */
		TEXT_VALID_LOOP(0, "2 200100107B1A74DF365639CC39F1D578 "
				   "AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cI"
				   "vM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbW"
				   "Iy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+b"
				   "SRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWx"
				   "Z48AWkskmdHaVDP4BcelrTI3rMXdXF5D"),
		TEXT_VALID_LOOP(1, "2 200100107B1A74DF365639CC39F1D578 "
				   "AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cI"
				   "vM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbW"
				   "Iy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+b"
				   "SRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWx"
				   "Z48AWkskmdHaVDP4BcelrTI3rMXdXF5D "
				   "rvs1.example.com."),
		TEXT_VALID_LOOP(2, "2 200100107B1A74DF365639CC39F1D578 "
				   "AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cI"
				   "vM4p9+LrV4e19WzK00+CI6zBCQTdtWsuxKbW"
				   "Iy87UOoJTwkUs7lBu+Upr1gsNrut79ryra+b"
				   "SRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWx"
				   "Z48AWkskmdHaVDP4BcelrTI3rMXdXF5D "
				   "rvs1.example.com. rvs2.example.com."),
		/*
		 * Sentinel.
		 */
		TEXT_SENTINEL()
	};
	unsigned char hipwire[DNS_RDATA_MAXLENGTH] = { 0x01, 0x00, 0x00, 0x01,
						       0x00, 0x00, 0x04, 0x41,
						       0x42, 0x43, 0x44, 0x00 };
	unsigned char buf[1024 * 1024];
	dns_rdata_t rdata = DNS_RDATA_INIT;
	isc_result_t result;
	size_t i;

	/*
	 * Fill the rest of input buffer with compression pointers.
	 */
	for (i = 12; i < sizeof(hipwire) - 2; i += 2) {
		hipwire[i] = 0xc0;
		hipwire[i + 1] = 0x06;
	}

	result = wire_to_rdata(hipwire, sizeof(hipwire), dns_rdataclass_in,
			       dns_rdatatype_hip, buf, sizeof(buf), &rdata);
	assert_int_equal(result, DNS_R_FORMERR);
	check_text_ok(text_ok, dns_rdataclass_in, dns_rdatatype_hip,
		      sizeof(dns_rdata_hip_t));
}

/*
 * ISDN tests.
 *
 * RFC 1183:
 *
 * 3.2. The ISDN RR
 *
 *    The ISDN RR is defined with mnemonic ISDN and type code 20 (decimal).
 *
 *    An ISDN (Integrated Service Digital Network) number is simply a
 *    telephone number.  The intent of the members of the CCITT is to
 *    upgrade all telephone and data network service to a common service.
 *
 *    The numbering plan (E.163/E.164) is the same as the familiar
 *    international plan for POTS (an un-official acronym, meaning Plain
 *    Old Telephone Service).  In E.166, CCITT says "An E.163/E.164
 *    telephony subscriber may become an ISDN subscriber without a number
 *    change."
 *
 *    ISDN has the following format:
 *
 *    <owner> <ttl> <class> ISDN <ISDN-address> <sa>
 *
 *    The <ISDN-address> field is required; <sa> is optional.
 *
 *    <ISDN-address> identifies the ISDN number of <owner> and DDI (Direct
 *    Dial In) if any, as defined by E.164 [8] and E.163 [7], the ISDN and
 *    PSTN (Public Switched Telephone Network) numbering plan.  E.163
 *    defines the country codes, and E.164 the form of the addresses.  Its
 *    format in master files is a <character-string> syntactically
 *    identical to that used in TXT and HINFO.
 *
 *    <sa> specifies the subaddress (SA).  The format of <sa> in master
 *    files is a <character-string> syntactically identical to that used in
 *    TXT and HINFO.
 *
 *    The format of ISDN is class insensitive.  ISDN RRs cause no
 *    additional section processing.
 *
 *    The <ISDN-address> is a string of characters, normally decimal
 *    digits, beginning with the E.163 country code and ending with the DDI
 *    if any.  Note that ISDN, in Q.931, permits any IA5 character in the
 *    general case.
 *
 *    The <sa> is a string of hexadecimal digits.  For digits 0-9, the
 *    concrete encoding in the Q.931 call setup information element is
 *    identical to BCD.
 *
 *    For example:
 *
 *    Relay.Prime.COM.   IN   ISDN      150862028003217
 *    sh.Prime.COM.      IN   ISDN      150862028003217 004
 *
 *    (Note: "1" is the country code for the North American Integrated
 *    Numbering Area, i.e., the system of "area codes" familiar to people
 *    in those countries.)
 *
 *    The RR data is the ASCII representation of the digits.  It is encoded
 *    as one or two <character-string>s, i.e., count followed by
 *    characters.
 */
ISC_RUN_TEST_IMPL(isdn) {
	wire_ok_t wire_ok[] = { /*
				 * "".
				 */
				WIRE_VALID(0x00),
				/*
				 * "\001".
				 */
				WIRE_VALID(0x01, 0x01),
				/*
				 * "\001" "".
				 */
				WIRE_VALID(0x01, 0x01, 0x00),
				/*
				 * "\001" "\001".
				 */
				WIRE_VALID(0x01, 0x01, 0x01, 0x01),
				/*
				 * Sentinel.
				 */
				WIRE_SENTINEL()
	};

	check_rdata(NULL, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_isdn, sizeof(dns_rdata_isdn_t));
}

/*
 * KEY tests.
 */
ISC_RUN_TEST_IMPL(key) {
	wire_ok_t wire_ok[] = {
		/*
		 * RDATA is comprised of:
		 *
		 *   - 2 octets for Flags,
		 *   - 1 octet for Protocol,
		 *   - 1 octet for Algorithm,
		 *   - variable number of octets for Public Key.
		 *
		 * RFC 2535 section 3.1.2 states that if bits
		 * 0-1 of Flags are both set, the RR stops after
		 * the algorithm octet and thus its length must
		 * be 4 octets.  In any other case, though, the
		 * Public Key part must not be empty.
		 *
		 * Algorithms PRIVATEDNS (253) and PRIVATEOID (254)
		 * have an algorithm identifier embedded and the start
		 * of the public key.
		 */
		WIRE_INVALID(0x00), WIRE_INVALID(0x00, 0x00),
		WIRE_INVALID(0x00, 0x00, 0x00),
		WIRE_VALID(0xc0, 0x00, 0x00, 0x00),
		WIRE_INVALID(0xc0, 0x00, 0x00, 0x00, 0x00),
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00),
		WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x00),
		/* PRIVATEDNS example. without key data */
		WIRE_VALID(0x00, 0x00, 0x00, 253, 0x07, 'e', 'x', 'a', 'm', 'p',
			   'l', 'e', 0x00),
		/* PRIVATEDNS example. + keydata */
		WIRE_VALID(0x00, 0x00, 0x00, 253, 0x07, 'e', 'x', 'a', 'm', 'p',
			   'l', 'e', 0x00, 0x00),
		/* PRIVATEDNS compression pointer. */
		WIRE_INVALID(0x00, 0x00, 0x00, 253, 0xc0, 0x00, 0x00),
		/* PRIVATEOID */
		WIRE_INVALID(0x00, 0x00, 0x00, 254, 0x00),
		/* PRIVATEOID 1.3.6.1.4.1.2495 without key data */
		WIRE_VALID(0x00, 0x00, 0x00, 254, 0x09, 0x06, 0x07, 0x2b, 0x06,
			   0x01, 0x04, 0x01, 0x93, 0x3f),
		/* PRIVATEOID 1.3.6.1.4.1.2495 + keydata */
		WIRE_VALID(0x00, 0x00, 0x00, 254, 0x09, 0x06, 0x07, 0x2b, 0x06,
			   0x01, 0x04, 0x01, 0x93, 0x3f, 0x00),
		/* PRIVATEOID malformed OID - high-bit set on last octet */
		WIRE_INVALID(0x00, 0x00, 0x00, 254, 0x06, 0x07, 0x2b, 0x06,
			     0x01, 0x04, 0x01, 0x93, 0xbf, 0x00),
		/* PRIVATEOID malformed OID - wrong tag */
		WIRE_INVALID(0x00, 0x00, 0x00, 254, 0x09, 0x07, 0x07, 0x2b,
			     0x06, 0x01, 0x04, 0x01, 0x93, 0x3f, 0x00),
		WIRE_SENTINEL()
	};
	text_ok_t text_ok[] = { /* PRIVATEDNS example. */
				TEXT_VALID("0 0 253 B2V4YW1wbGUA"),
				/* PRIVATEDNS example. + keydata */
				TEXT_VALID("0 0 253 B2V4YW1wbGUAAA=="),
				/* PRIVATEDNS compression pointer. */
				TEXT_INVALID("0 0 253 wAAA"),
				/* PRIVATEOID */
				TEXT_INVALID("0 0 254 AA=="),
				/* PRIVATEOID 1.3.6.1.4.1.2495 */
				TEXT_VALID("0 0 254 CQYHKwYBBAGTPw=="),
				/* PRIVATEOID 1.3.6.1.4.1.2495 + keydata */
				TEXT_VALID("0 0 254 CQYHKwYBBAGTPwA="),
				/* PRIVATEOID malformed OID - high-bit set on
				   last octet */
				TEXT_INVALID("0 0 254 CQYHKwYBBAGTvwA="),
				/* PRIVATEOID malformed OID - wrong tag */
				TEXT_INVALID("0 0 254 CQcHKwYBBAGTPwA="),
				/*
				 * Sentinel.
				 */
				TEXT_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_key, sizeof(dns_rdata_key_t));
}

/*
 * LOC tests.
 */
ISC_RUN_TEST_IMPL(loc) {
	text_ok_t text_ok[] = {
		TEXT_VALID_CHANGED("0 N 0 E 0", "0 0 0.000 N 0 0 0.000 E 0.00m "
						"1m 10000m 10m"),
		TEXT_VALID_CHANGED("0 S 0 W 0", "0 0 0.000 N 0 0 0.000 E 0.00m "
						"1m 10000m 10m"),
		TEXT_VALID_CHANGED("0 0 N 0 0 E 0", "0 0 0.000 N 0 0 0.000 E "
						    "0.00m 1m 10000m 10m"),
		TEXT_VALID_CHANGED("0 0 0 N 0 0 0 E 0",
				   "0 0 0.000 N 0 0 0.000 E 0.00m 1m 10000m "
				   "10m"),
		TEXT_VALID_CHANGED("0 0 0 N 0 0 0 E 0",
				   "0 0 0.000 N 0 0 0.000 E 0.00m 1m 10000m "
				   "10m"),
		TEXT_VALID_CHANGED("0 0 0. N 0 0 0. E 0",
				   "0 0 0.000 N 0 0 0.000 E 0.00m 1m 10000m "
				   "10m"),
		TEXT_VALID_CHANGED("0 0 .0 N 0 0 .0 E 0",
				   "0 0 0.000 N 0 0 0.000 E 0.00m 1m 10000m "
				   "10m"),
		TEXT_INVALID("0 North 0 East 0"),
		TEXT_INVALID("0 South 0 West 0"),
		TEXT_INVALID("0 0 . N 0 0 0. E 0"),
		TEXT_INVALID("0 0 0. N 0 0 . E 0"),
		TEXT_INVALID("0 0 0. N 0 0 0. E m"),
		TEXT_INVALID("0 0 0. N 0 0 0. E 0 ."),
		TEXT_INVALID("0 0 0. N 0 0 0. E 0 m"),
		TEXT_INVALID("0 0 0. N 0 0 0. E 0 0 ."),
		TEXT_INVALID("0 0 0. N 0 0 0. E 0 0 m"),
		TEXT_INVALID("0 0 0. N 0 0 0. E 0 0 0 ."),
		TEXT_INVALID("0 0 0. N 0 0 0. E 0 0 0 m"),
		TEXT_VALID_CHANGED("90 N 180 E 0", "90 0 0.000 N 180 0 0.000 E "
						   "0.00m 1m 10000m 10m"),
		TEXT_INVALID("90 1 N 180 E 0"),
		TEXT_INVALID("90 0 1 N 180 E 0"),
		TEXT_INVALID("90 N 180 1 E 0"),
		TEXT_INVALID("90 N 180 0 1 E 0"),
		TEXT_VALID_CHANGED("90 S 180 W 0", "90 0 0.000 S 180 0 0.000 W "
						   "0.00m 1m 10000m 10m"),
		TEXT_INVALID("90 1 S 180 W 0"),
		TEXT_INVALID("90 0 1 S 180 W 0"),
		TEXT_INVALID("90 S 180 1 W 0"),
		TEXT_INVALID("90 S 180 0 1 W 0"),
		TEXT_INVALID("0 0 0.000 E 0 0 0.000 E -0.95m 1m 10000m 10m"),
		TEXT_VALID("0 0 0.000 N 0 0 0.000 E -0.95m 1m 10000m 10m"),
		TEXT_VALID("0 0 0.000 N 0 0 0.000 E -0.05m 1m 10000m 10m"),
		TEXT_VALID("0 0 0.000 N 0 0 0.000 E -100000.00m 1m 10000m 10m"),
		TEXT_VALID("0 0 0.000 N 0 0 0.000 E 42849672.95m 1m 10000m "
			   "10m"),
		/*
		 * Sentinel.
		 */
		TEXT_SENTINEL()
	};

	check_rdata(text_ok, 0, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_loc, sizeof(dns_rdata_loc_t));
}

/*
 * http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
 *
 * The RDATA portion of both the NIMLOC and EID records contains
 * uninterpreted binary data.  The representation in the text master file
 * is an even number of hex characters (0 to 9, a to f), case is not
 * significant.  For readability, whitespace may be included in the value
 * field and should be ignored when reading a master file.
 */
ISC_RUN_TEST_IMPL(nimloc) {
	text_ok_t text_ok[] = { TEXT_VALID("AABBCC"),
				TEXT_VALID_CHANGED("AA bb cc", "AABBCC"),
				TEXT_INVALID("aab"),
				/*
				 * Sentinel.
				 */
				TEXT_SENTINEL() };
	wire_ok_t wire_ok[] = { WIRE_VALID(0x00), WIRE_VALID(0xAA, 0xBB, 0xCC),
				/*
				 * Sentinel.
				 */
				WIRE_SENTINEL() };

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_nimloc, sizeof(dns_rdata_in_nimloc_t));
}

/*
 * NSEC tests.
 *
 * RFC 4034:
 *
 * 4.1.  NSEC RDATA Wire Format
 *
 *   The RDATA of the NSEC RR is as shown below:
 *
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    /                      Next Domain Name                         /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    /                       Type Bit Maps                           /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 4.1.1.  The Next Domain Name Field
 *
 *    The Next Domain field contains the next owner name (in the canonical
 *    ordering of the zone) that has authoritative data or contains a
 *    delegation point NS RRset; see Section 6.1 for an explanation of
 *    canonical ordering.  The value of the Next Domain Name field in the
 *    last NSEC record in the zone is the name of the zone apex (the owner
 *    name of the zone's SOA RR).  This indicates that the owner name of
 *    the NSEC RR is the last name in the canonical ordering of the zone.
 *
 *    A sender MUST NOT use DNS name compression on the Next Domain Name
 *    field when transmitting an NSEC RR.
 *
 *    Owner names of RRsets for which the given zone is not authoritative
 *    (such as glue records) MUST NOT be listed in the Next Domain Name
 *    unless at least one authoritative RRset exists at the same owner
 *    name.
 *
 * 4.1.2.  The Type Bit Maps Field
 *
 *    The Type Bit Maps field identifies the RRset types that exist at the
 *    NSEC RR's owner name.
 *
 *    The RR type space is split into 256 window blocks, each representing
 *    the low-order 8 bits of the 16-bit RR type space.  Each block that
 *    has at least one active RR type is encoded using a single octet
 *    window number (from 0 to 255), a single octet bitmap length (from 1
 *    to 32) indicating the number of octets used for the window block's
 *    bitmap, and up to 32 octets (256 bits) of bitmap.
 *
 *    Blocks are present in the NSEC RR RDATA in increasing numerical
 *    order.
 *
 *       Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+
 *
 *       where "|" denotes concatenation.
 *
 *    Each bitmap encodes the low-order 8 bits of RR types within the
 *    window block, in network bit order.  The first bit is bit 0.  For
 *    window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
 *    to RR type 2 (NS), and so forth.  For window block 1, bit 1
 *    corresponds to RR type 257, and bit 2 to RR type 258.  If a bit is
 *    set, it indicates that an RRset of that type is present for the NSEC
 *    RR's owner name.  If a bit is clear, it indicates that no RRset of
 *    that type is present for the NSEC RR's owner name.
 *
 *    Bits representing pseudo-types MUST be clear, as they do not appear
 *    in zone data.  If encountered, they MUST be ignored upon being read.
 */
ISC_RUN_TEST_IMPL(nsec) {
	text_ok_t text_ok[] = { TEXT_INVALID(""), TEXT_INVALID("."),
				TEXT_VALID(". RRSIG"), TEXT_SENTINEL() };
	wire_ok_t wire_ok[] = { WIRE_INVALID(0x00), WIRE_INVALID(0x00, 0x00),
				WIRE_INVALID(0x00, 0x00, 0x00),
				WIRE_VALID(0x00, 0x00, 0x01, 0x02),
				WIRE_SENTINEL() };

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_nsec, sizeof(dns_rdata_nsec_t));
}

/*
 * NSEC3 tests.
 *
 * RFC 5155.
 */
ISC_RUN_TEST_IMPL(nsec3) {
	text_ok_t text_ok[] = { TEXT_INVALID(""),
				TEXT_INVALID("."),
				TEXT_INVALID(". RRSIG"),
				TEXT_INVALID("1 0 10 76931F"),
				TEXT_INVALID("1 0 10 76931F "
					     "IMQ912BREQP1POLAH3RMONG&"
					     "UED541AS"),
				TEXT_INVALID("1 0 10 76931F "
					     "IMQ912BREQP1POLAH3RMONGAUED541AS "
					     "A RRSIG BADTYPE"),
				TEXT_VALID("1 0 10 76931F "
					   "AJHVGTICN6K0VDA53GCHFMT219SRRQLM A "
					   "RRSIG"),
				TEXT_VALID("1 0 10 76931F "
					   "AJHVGTICN6K0VDA53GCHFMT219SRRQLM"),
				TEXT_VALID("1 0 10 - "
					   "AJHVGTICN6K0VDA53GCHFMT219SRRQLM"),
				TEXT_SENTINEL() };

	check_rdata(text_ok, NULL, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_nsec3, sizeof(dns_rdata_nsec3_t));
}

/* NXT RDATA manipulations */
ISC_RUN_TEST_IMPL(nxt) {
	compare_ok_t compare_ok[] = {
		COMPARE("a. A SIG", "a. A SIG", 0),
		/*
		 * Records that differ only in the case of the next
		 * name should be equal.
		 */
		COMPARE("A. A SIG", "a. A SIG", 0),
		/*
		 * Sorting on name field.
		 */
		COMPARE("A. A SIG", "b. A SIG", -1),
		COMPARE("b. A SIG", "A. A SIG", 1),
		/* bit map differs */
		COMPARE("b. A SIG", "b. A AAAA SIG", -1),
		/* order of bit map does not matter */
		COMPARE("b. A SIG AAAA", "b. A AAAA SIG", 0), COMPARE_SENTINEL()
	};

	check_rdata(NULL, NULL, compare_ok, false, dns_rdataclass_in,
		    dns_rdatatype_nxt, sizeof(dns_rdata_nxt_t));
}

ISC_RUN_TEST_IMPL(rkey) {
	text_ok_t text_ok[] = { /*
				 * Valid, flags set to 0 and a key is present.
				 */
				TEXT_VALID("0 0 0 aaaa"),
				/*
				 * Invalid, non-zero flags.
				 */
				TEXT_INVALID("1 0 0 aaaa"),
				TEXT_INVALID("65535 0 0 aaaa"),
				/*
				 * Sentinel.
				 */
				TEXT_SENTINEL()
	};
	wire_ok_t wire_ok[] = { /*
				 * Valid, flags set to 0 and a key is present.
				 */
				WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x00),
				/*
				 * Invalid, non-zero flags.
				 */
				WIRE_INVALID(0x00, 0x01, 0x00, 0x00, 0x00),
				WIRE_INVALID(0xff, 0xff, 0x00, 0x00, 0x00),
				/*
				 * Sentinel.
				 */
				WIRE_SENTINEL()
	};
	key_required(state, dns_rdatatype_rkey, sizeof(dns_rdata_rkey_t));
	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_rkey, sizeof(dns_rdata_rkey_t));
}

ISC_RUN_TEST_IMPL(resinfo) {
	text_ok_t text_ok[] = {
		TEXT_VALID_CHANGED("qnamemin exterr=15,16,17 "
				   "infourl=https://resolver.example.com/guide",
				   "\"qnamemin\" \"exterr=15,16,17\" "
				   "\"infourl=https://resolver.example.com/"
				   "guide\""),
		/*
		 * Sentinel.
		 */
		TEXT_SENTINEL()
	};
	check_rdata(text_ok, NULL, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_resinfo, sizeof(dns_rdata_rkey_t));
}

/* SSHFP RDATA manipulations */
ISC_RUN_TEST_IMPL(sshfp) {
	text_ok_t text_ok[] = { TEXT_INVALID(""),     /* too short */
				TEXT_INVALID("0"),    /* reserved, too short */
				TEXT_VALID("0 0"),    /* no finger print */
				TEXT_VALID("0 0 AA"), /* reserved */
				TEXT_INVALID("0 1 AA"), /* too short SHA 1
							 * digest */
				TEXT_INVALID("0 2 AA"), /* too short SHA 256
							 * digest */
				TEXT_VALID("0 3 AA"),	/* unknown finger print
							 * type */
				/* good length SHA 1 digest */
				TEXT_VALID("1 1 "
					   "00112233445566778899AABBCCDDEEFF171"
					   "81920"),
				/* good length SHA 256 digest */
				TEXT_VALID("4 2 "
					   "A87F1B687AC0E57D2A081A2F282672334D9"
					   "0ED316D2B818CA9580EA3 84D92401"),
				/*
				 * totext splits the fingerprint into chunks and
				 * emits uppercase hex.
				 */
				TEXT_VALID_CHANGED("1 2 "
						   "00112233445566778899aabbccd"
						   "deeff "
						   "00112233445566778899AABBCCD"
						   "DEEFF",
						   "1 2 "
						   "00112233445566778899AABBCCD"
						   "DEEFF"
						   "00112233445566778899AABB "
						   "CCDDEEFF"),
				TEXT_SENTINEL() };
	wire_ok_t wire_ok[] = {
		WIRE_INVALID(0x00),	      /* reserved too short */
		WIRE_VALID(0x00, 0x00),	      /* reserved no finger print */
		WIRE_VALID(0x00, 0x00, 0x00), /* reserved */

		/* too short SHA 1 digests */
		WIRE_INVALID(0x00, 0x01), WIRE_INVALID(0x00, 0x01, 0x00),
		WIRE_INVALID(0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			     0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
			     0xEE, 0xFF, 0x17, 0x18, 0x19),
		/* good length SHA 1 digest */
		WIRE_VALID(0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
			   0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			   0x17, 0x18, 0x19, 0x20),
		/* too long SHA 1 digest */
		WIRE_INVALID(0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			     0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
			     0xEE, 0xFF, 0x17, 0x18, 0x19, 0x20, 0x21),
		/* too short SHA 256 digests */
		WIRE_INVALID(0x00, 0x02), WIRE_INVALID(0x00, 0x02, 0x00),
		WIRE_INVALID(0x00, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			     0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
			     0xEE, 0xFF, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22,
			     0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
			     0x31),
		/* good length SHA 256 digest */
		WIRE_VALID(0x00, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
			   0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
			   0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
			   0x26, 0x27, 0x28, 0x29, 0x30, 0x31, 0x32),
		/* too long SHA 256 digest */
		WIRE_INVALID(0x00, 0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
			     0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
			     0xEE, 0xFF, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22,
			     0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30,
			     0x31, 0x32, 0x33),
		/* unknown digest, * no fingerprint */
		WIRE_VALID(0x00, 0x03), WIRE_VALID(0x00, 0x03, 0x00), /* unknown
								       * digest
								       */
		WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_sshfp, sizeof(dns_rdata_sshfp_t));
}

ISC_RUN_TEST_IMPL(wallet) {
	text_ok_t text_ok[] = { TEXT_VALID_CHANGED("cid-example wid-example",
						   "\"cid-example\" "
						   "\"wid-example\""),
				/*
				 * Sentinel.
				 */
				TEXT_SENTINEL() };
	check_rdata(text_ok, NULL, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_wallet, sizeof(dns_rdata_rkey_t));
}

/*
 * WKS tests.
 *
 * RFC 1035:
 *
 * 3.4.2. WKS RDATA format
 *
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ADDRESS                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |       PROTOCOL        |                       |
 *     +--+--+--+--+--+--+--+--+                       |
 *     |                                               |
 *     /                   <BIT MAP>                   /
 *     /                                               /
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * where:
 *
 * ADDRESS         An 32 bit Internet address
 *
 * PROTOCOL        An 8 bit IP protocol number
 *
 * <BIT MAP>       A variable length bit map.  The bit map must be a
 *                 multiple of 8 bits long.
 *
 * The WKS record is used to describe the well known services supported by
 * a particular protocol on a particular internet address.  The PROTOCOL
 * field specifies an IP protocol number, and the bit map has one bit per
 * port of the specified protocol.  The first bit corresponds to port 0,
 * the second to port 1, etc.  If the bit map does not include a bit for a
 * protocol of interest, that bit is assumed zero.  The appropriate values
 * and mnemonics for ports and protocols are specified in [RFC-1010].
 *
 * For example, if PROTOCOL=TCP (6), the 26th bit corresponds to TCP port
 * 25 (SMTP).  If this bit is set, a SMTP server should be listening on TCP
 * port 25; if zero, SMTP service is not supported on the specified
 * address.
 */
ISC_RUN_TEST_IMPL(wks) {
	text_ok_t text_ok[] = { /*
				 * Valid, IPv4 address in dotted-quad form.
				 */
				TEXT_VALID("127.0.0.1 6"),
				/*
				 * Invalid, IPv4 address not in dotted-quad
				 * form.
				 */
				TEXT_INVALID("127.1 6"),
				/*
				 * Sentinel.
				 */
				TEXT_SENTINEL()
	};
	wire_ok_t wire_ok[] = { /*
				 * Too short.
				 */
				WIRE_INVALID(0x00, 0x08, 0x00, 0x00),
				/*
				 * Minimal TCP.
				 */
				WIRE_VALID(0x00, 0x08, 0x00, 0x00, 6),
				/*
				 * Minimal UDP.
				 */
				WIRE_VALID(0x00, 0x08, 0x00, 0x00, 17),
				/*
				 * Minimal other.
				 */
				WIRE_VALID(0x00, 0x08, 0x00, 0x00, 1),
				/*
				 * Sentinel.
				 */
				WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_wks, sizeof(dns_rdata_in_wks_t));
}

ISC_RUN_TEST_IMPL(https_svcb) {
	/*
	 * Known keys: mandatory, apln, no-default-alpn, port,
	 *             ipv4hint, port, ipv6hint, dohpath.
	 */
	text_ok_t text_ok[] = {
		/* unknown key invalid */
		TEXT_INVALID("1 . unknown="),
		/* no domain */
		TEXT_INVALID("0"),
		/* minimal record */
		TEXT_VALID_LOOP(0, "0 ."),
		/* Alias form possible future extension */
		TEXT_VALID_LOOP(1, "0 . alpn=\"h2\""),
		/* no "key" prefix */
		TEXT_INVALID("2 svc.example.net. 0=\"2222\""),
		/* no key value */
		TEXT_INVALID("2 svc.example.net. key"),
		/* no key value */
		TEXT_INVALID("2 svc.example.net. key=\"2222\""),
		/* zero pad invalid */
		TEXT_INVALID("2 svc.example.net. key07=\"2222\""),
		TEXT_VALID_LOOP(1, "2 svc.example.net. key8=\"2222\""),
		TEXT_VALID_LOOPCHG(1, "2 svc.example.net. key8=2222",
				   "2 svc.example.net. key8=\"2222\""),
		TEXT_VALID_LOOPCHG(1, "2 svc.example.net. alpn=h2",
				   "2 svc.example.net. alpn=\"h2\""),
		TEXT_VALID_LOOPCHG(1, "2 svc.example.net. alpn=h3",
				   "2 svc.example.net. alpn=\"h3\""),
		/* alpn has 2 sub field "h2" and "h3" */
		TEXT_VALID_LOOPCHG(1, "2 svc.example.net. alpn=h2,h3",
				   "2 svc.example.net. alpn=\"h2,h3\""),
		/* apln has 2 sub fields "h1,h2" and "h3" (comma escaped) */
		TEXT_VALID_LOOPCHG(1, "2 svc.example.net. alpn=h1\\\\,h2,h3",
				   "2 svc.example.net. alpn=\"h1\\\\,h2,h3\""),
		TEXT_VALID_LOOP(1, "2 svc.example.net. port=50"),
		/* no-default-alpn, alpn is required */
		TEXT_INVALID("2 svc.example.net. no-default-alpn"),
		/* no-default-alpn with alpn present */
		TEXT_VALID_LOOPCHG(
			2, "2 svc.example.net. no-default-alpn alpn=h2",
			"2 svc.example.net. alpn=\"h2\" no-default-alpn"),
		/* empty hint */
		TEXT_INVALID("2 svc.example.net. ipv4hint="),
		TEXT_VALID_LOOP(1, "2 svc.example.net. "
				   "ipv4hint=10.50.0.1,10.50.0.2"),
		/* empty hint */
		TEXT_INVALID("2 svc.example.net. ipv6hint="),
		TEXT_VALID_LOOP(1, "2 svc.example.net. ipv6hint=::1,2002::1"),
		TEXT_VALID_LOOP(1, "2 svc.example.net. ech=abcdefghijkl"),
		/* bad base64 */
		TEXT_INVALID("2 svc.example.net. ech=abcdefghijklm"),
		TEXT_VALID_LOOP(1, "2 svc.example.net. key8=\"2222\""),
		/* Out of key order on input (alpn == key1). */
		TEXT_VALID_LOOPCHG(2,
				   "2 svc.example.net. key8=\"2222\" alpn=h2",
				   "2 svc.example.net. alpn=\"h2\" "
				   "key8=\"2222\""),
		TEXT_VALID_LOOP(1, "2 svc.example.net. key65535=\"2222\""),
		TEXT_INVALID("2 svc.example.net. key65536=\"2222\""),
		TEXT_VALID_LOOP(1, "2 svc.example.net. key10"),
		TEXT_VALID_LOOPCHG(1, "2 svc.example.net. key11=",
				   "2 svc.example.net. key11"),
		TEXT_VALID_LOOPCHG(1, "2 svc.example.net. key12=\"\"",
				   "2 svc.example.net. key12"),
		/* empty alpn-id sub fields */
		TEXT_INVALID("2 svc.example.net. alpn"),
		TEXT_INVALID("2 svc.example.net. alpn="),
		TEXT_INVALID("2 svc.example.net. alpn=,h1"),
		TEXT_INVALID("2 svc.example.net. alpn=h1,"),
		TEXT_INVALID("2 svc.example.net. alpn=h1,,h2"),
		/* empty alpn-id sub fields - RFC 1035 escaped commas */
		TEXT_INVALID("2 svc.example.net. alpn=\\,abc"),
		TEXT_INVALID("2 svc.example.net. alpn=abc\\,"),
		TEXT_INVALID("2 svc.example.net. alpn=a\\,\\,abc"),
		/* mandatory */
		TEXT_VALID_LOOP(2, "2 svc.example.net. mandatory=alpn "
				   "alpn=\"h2\""),
		TEXT_VALID_LOOP(3, "2 svc.example.net. mandatory=alpn,port "
				   "alpn=\"h2\" port=443"),
		TEXT_VALID_LOOPCHG(3,
				   "2 svc.example.net. mandatory=port,alpn "
				   "alpn=\"h2\" port=443",
				   "2 svc.example.net. mandatory=alpn,port "
				   "alpn=\"h2\" port=443"),
		TEXT_INVALID("2 svc.example.net. mandatory=mandatory"),
		TEXT_INVALID("2 svc.example.net. mandatory=port"),
		TEXT_INVALID("2 svc.example.net. mandatory=,port port=433"),
		TEXT_INVALID("2 svc.example.net. mandatory=port, port=433"),
		TEXT_INVALID("2 svc.example.net. "
			     "mandatory=alpn,,port alpn=h2 port=433"),
		/* mandatory w/ unknown key values */
		TEXT_VALID_LOOP(2, "2 svc.example.net. mandatory=key8 key8"),
		TEXT_VALID_LOOP(3, "2 svc.example.net. mandatory=key8,key9 "
				   "key8 key9"),
		TEXT_VALID_LOOPCHG(
			3, "2 svc.example.net. mandatory=key9,key8 key8 key9",
			"2 svc.example.net. mandatory=key8,key9 key8 key9"),
		TEXT_INVALID("2 svc.example.net. "
			     "mandatory=key8,key8"),
		TEXT_INVALID("2 svc.example.net. mandatory=,key8"),
		TEXT_INVALID("2 svc.example.net. mandatory=key8,"),
		TEXT_INVALID("2 svc.example.net. "
			     "mandatory=key8,,key8"),
		/* Invalid test vectors */
		TEXT_INVALID("1 foo.example.com. ( key123=abc key123=def )"),
		TEXT_INVALID("1 foo.example.com. mandatory"),
		TEXT_INVALID("1 foo.example.com. alpn"),
		TEXT_INVALID("1 foo.example.com. port"),
		TEXT_INVALID("1 foo.example.com. ipv4hint"),
		TEXT_INVALID("1 foo.example.com. ipv6hint"),
		TEXT_INVALID("1 foo.example.com. no-default-alpn=abc"),
		TEXT_INVALID("1 foo.example.com. mandatory=key123"),
		TEXT_INVALID("1 foo.example.com. mandatory=mandatory"),
		TEXT_INVALID("1 foo.example.com. ( mandatory=key123,key123 "
			     "key123=abc)"),
		/* dohpath tests */
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=/{dns}",
				   "1 example.net. key7=\"/{dns}\""),
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=/{+dns}",
				   "1 example.net. key7=\"/{+dns}\""),
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=/{#dns}",
				   "1 example.net. key7=\"/{#dns}\""),
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=/{.dns}",
				   "1 example.net. key7=\"/{.dns}\""),
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=\"/{;dns}\"",
				   "1 example.net. key7=\"/{;dns}\""),
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=/{?dns}",
				   "1 example.net. key7=\"/{?dns}\""),
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=/some/path{?dns}",
				   "1 example.net. key7=\"/some/path{?dns}\""),
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=/{dns:9999}",
				   "1 example.net. key7=\"/{dns:9999}\""),
		TEXT_VALID_LOOPCHG(1, "1 example.net. dohpath=/{dns*}",
				   "1 example.net. key7=\"/{dns*}\""),
		TEXT_VALID_LOOPCHG(
			1, "1 example.net. dohpath=/some/path?key=value{&dns}",
			"1 example.net. key7=\"/some/path?key=value{&dns}\""),
		TEXT_VALID_LOOPCHG(1,
				   "1 example.net. "
				   "dohpath=/some/path?key=value{&dns,x*}",
				   "1 example.net. "
				   "key7=\"/some/path?key=value{&dns,x*}\""),
		TEXT_INVALID("1 example.com. dohpath=not-relative"),
		TEXT_INVALID("1 example.com. dohpath=/{?no_dns_variable}"),
		TEXT_INVALID("1 example.com. dohpath=/novariable"),
		TEXT_INVALID("1 example.com. dohpath=/{?dnsx}"),
		/* index too big > 9999 */
		TEXT_INVALID("1 example.com. dohpath=/{?dns:10000}"),
		/* index not postive */
		TEXT_INVALID("1 example.com. dohpath=/{?dns:0}"),
		/* index leading zero */
		TEXT_INVALID("1 example.com. dohpath=/{?dns:01}"),
		/* two operators */
		TEXT_INVALID("1 example.com. dohpath=/{??dns}"),
		/* invalid % encoding */
		TEXT_INVALID("1 example.com. dohpath=/%a{?dns}"),
		/* invalid % encoding */
		TEXT_INVALID("1 example.com. dohpath=/{?dns,%a}"),
		/* incomplete macro */
		TEXT_INVALID("1 example.com. dohpath=/{?dns" /*}*/),
		TEXT_SENTINEL()

	};
	wire_ok_t wire_ok[] = {
		/*
		 * Too short
		 */
		WIRE_INVALID(0x00, 0x00),
		/*
		 * Minimal length record.
		 */
		WIRE_VALID(0x00, 0x00, 0x00),
		/*
		 * Alias with invalid dohpath.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00),
		/*
		 * Bad key7= length (longer than rdata).
		 */
		WIRE_INVALID(0x00, 0x01, 0x00, 0x00, 0x07, 0x00, 0x01),
		/*
		 * Port (0x03) too small (zero and one octets).
		 */
		WIRE_INVALID(0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00),
		WIRE_INVALID(0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00),
		/* Valid port */
		WIRE_VALID_LOOP(1, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x02,
				0x00, 0x00),
		/*
		 * Port (0x03) too big (three octets).
		 */
		WIRE_INVALID(0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00,
			     0x00, 0x00),
		/*
		 * Duplicate keys.
		 */
		WIRE_INVALID(0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
			     0x80, 0x00, 0x00),
		/*
		 * Out of order keys.
		 */
		WIRE_INVALID(0x01, 0x01, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00,
			     0x80, 0x00, 0x00),
		/*
		 * Empty of mandatory key list.
		 */
		WIRE_INVALID(0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * "mandatory=mandatory" is invalid
		 */
		WIRE_INVALID(0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
			     0x00),
		/*
		 * Out of order mandatory key list.
		 */
		WIRE_INVALID(0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
			     0x80, 0x00, 0x71, 0x00, 0x71, 0x00, 0x00, 0x00,
			     0x80, 0x00, 0x00),
		/*
		 * Alpn(0x00 0x01) (length 0x00 0x09) "h1,h2" + "h3"
		 */
		WIRE_VALID_LOOP(0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x09,
				5, 'h', '1', ',', 'h', '2', 2, 'h', '3'),
		/*
		 * Alpn(0x00 0x01) (length 0x00 0x09) "h1\h2" + "h3"
		 */
		WIRE_VALID_LOOP(0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x09,
				5, 'h', '1', '\\', 'h', '2', 2, 'h', '3'),
		/*
		 * no-default-alpn (0x00 0x02) without alpn, alpn is required.
		 */
		WIRE_INVALID(0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00),
		/*
		 * Alpn(0x00 0x01) with zero length elements is invalid
		 */
		WIRE_INVALID(0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x05,
			     0x00, 0x00, 0x00, 0x00, 0x00),
		WIRE_SENTINEL()
	};
	/* Test vectors from RFCXXXX */
	textvsunknown_t textvsunknown[] = {
		/* AliasForm */
		{ "0 foo.example.com", "\\# 19 ( 00 00 03 66 6f 6f 07 65 78 61 "
				       "6d 70 6c 65 03 63 6f 6d 00)" },
		/* ServiceForm */
		{ "1 .", "\\# 3 ( 00 01 00)" },
		/* Port example */
		{ "16 foo.example.com port=53",
		  "\\# 25 ( 00 10 03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f "
		  "6d 00 00 03 00 02 00 35 )" },
		/* Unregistered keys with unquoted value. */
		{ "1 foo.example.com key667=hello",
		  "\\# 28 ( 00 01 03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f "
		  "6d 00 02 9b 00 05 68 65 6c 6c 6f )" },
		/*
		 * Quoted decimal-escaped character.
		 * 1 foo.example.com key667="hello\210qoo"
		 */
		{ "1 foo.example.com key667=\"hello\\210qoo\"",
		  "\\# 32 ( 00 01 03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f "
		  "6d 00 02 9b 00 09 68 65 6c 6c 6f d2 71 6f 6f )" },
		/*
		 * IPv6 hints example, quoted.
		 * 1 foo.example.com ipv6hint="2001:db8::1,2001:db8::53:1"
		 */
		{ "1 foo.example.com ipv6hint=\"2001:db8::1,2001:db8::53:1\"",
		  "\\# 55 ( 00 01 03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f "
		  "6d 00 00 06 00 20 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 "
		  "00 01 20 01 0d b8 00 00 00 00 00 00 00 00 00 53 00 01 )" },
		/* SvcParamValues and mandatory out of order. */
		{ "16 foo.example.org alpn=h2,h3-19 mandatory=ipv4hint,alpn "
		  "ipv4hint=192.0.2.1",
		  "\\# 48 ( 00 10 03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 "
		  "67 00 00 00 00 04 00 01 00 04 00 01 00 09 02 68 32 05 68 33 "
		  "2d 31 39 00 04 00 04 c0 00 02 01 )" },
		/*
		 * Quoted ALPN with escaped comma and backslash.
		 * 16 foo.example.org alpn="f\\\\oo\\,bar,h2"
		 */
		{ "16 foo.example.org alpn=\"f\\\\\\\\oo\\\\,bar,h2\"",
		  "\\# 35 ( 00 10 03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 "
		  "67 00 00 01 00 0c 08 66 5c 6f 6f 2c 62 61 72 02 68 32 )" },
		/*
		 * Unquoted ALPN with escaped comma and backslash.
		 * 16 foo.example.org alpn=f\\\092oo\092,bar,h2
		 */
		{ "16 foo.example.org alpn=f\\\\\\092oo\\092,bar,h2",
		  "\\# 35 ( 00 10 03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 "
		  "67 00 00 01 00 0c 08 66 5c 6f 6f 2c 62 61 72 02 68 32 )" },
		{ NULL, NULL }
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_svcb, sizeof(dns_rdata_in_svcb_t));
	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_https, sizeof(dns_rdata_in_https_t));

	check_textvsunknown(textvsunknown, dns_rdataclass_in,
			    dns_rdatatype_svcb);
	check_textvsunknown(textvsunknown, dns_rdataclass_in,
			    dns_rdatatype_https);
}

/*
 * ZONEMD tests.
 *
 * Excerpted from RFC 8976:
 *
 * The ZONEMD RDATA wire format is encoded as follows:
 *
 *                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                             Serial                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |    Scheme     |Hash Algorithm |                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
 *    |                             Digest                            |
 *    /                                                               /
 *    /                                                               /
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 2.2.1.  The Serial Field
 *
 *    The Serial field is a 32-bit unsigned integer in network byte order.
 *    It is the serial number from the zone's SOA record ([RFC1035],
 *    Section 3.3.13) for which the zone digest was generated.
 *
 *    It is included here to clearly bind the ZONEMD RR to a particular
 *    version of the zone's content.  Without the serial number, a stand-
 *    alone ZONEMD digest has no obvious association to any particular
 *    instance of a zone.
 *
 * 2.2.2.  The Scheme Field
 *
 *    The Scheme field is an 8-bit unsigned integer that identifies the
 *    methods by which data is collated and presented as input to the
 *    hashing function.
 *
 *    Herein, SIMPLE, with Scheme value 1, is the only standardized Scheme
 *    defined for ZONEMD records and it MUST be supported by
 *    implementations.  The "ZONEMD Schemes" registry is further described
 *    in Section 5.
 *
 *    Scheme values 240-254 are allocated for Private Use.
 *
 * 2.2.3.  The Hash Algorithm Field
 *
 *    The Hash Algorithm field is an 8-bit unsigned integer that identifies
 *    the cryptographic hash algorithm used to construct the digest.
 *
 *    Herein, SHA384 ([RFC6234]), with Hash Algorithm value 1, is the only
 *    standardized Hash Algorithm defined for ZONEMD records that MUST be
 *    supported by implementations.  When SHA384 is used, the size of the
 *    Digest field is 48 octets.  The result of the SHA384 digest algorithm
 *    MUST NOT be truncated, and the entire 48-octet digest is published in
 *    the ZONEMD record.
 *
 *    SHA512 ([RFC6234]), with Hash Algorithm value 2, is also defined for
 *    ZONEMD records and SHOULD be supported by implementations.  When
 *    SHA512 is used, the size of the Digest field is 64 octets.  The
 *    result of the SHA512 digest algorithm MUST NOT be truncated, and the
 *    entire 64-octet digest is published in the ZONEMD record.
 *
 *    Hash Algorithm values 240-254 are allocated for Private Use.
 *
 *    The "ZONEMD Hash Algorithms" registry is further described in
 *    Section 5.
 *
 * 2.2.4.  The Digest Field
 *
 *    The Digest field is a variable-length sequence of octets containing
 *    the output of the hash algorithm.  The length of the Digest field is
 *    determined by deducting the fixed size of the Serial, Scheme, and
 *    Hash Algorithm fields from the RDATA size in the ZONEMD RR header.
 *
 *    The Digest field MUST NOT be shorter than 12 octets.  Digests for the
 *    SHA384 and SHA512 hash algorithms specified herein are never
 *    truncated.  Digests for future hash algorithms MAY be truncated but
 *    MUST NOT be truncated to a length that results in less than 96 bits
 *    (12 octets) of equivalent strength.
 *
 *    Section 3 describes how to calculate the digest for a zone.
 *    Section 4 describes how to use the digest to verify the contents of a
 *    zone.
 *
 */

ISC_RUN_TEST_IMPL(zonemd) {
	text_ok_t text_ok[] = {
		TEXT_INVALID(""),
		/* No digest scheme or digest type*/
		TEXT_INVALID("0"),
		/* No digest type */
		TEXT_INVALID("0 0"),
		/* No digest */
		TEXT_INVALID("0 0 0"),
		/* No digest */
		TEXT_INVALID("99999999 0 0"),
		/* No digest */
		TEXT_INVALID("2019020700 0 0"),
		/* Digest too short */
		TEXT_INVALID("2019020700 1 1 DEADBEEF"),
		/* Digest too short */
		TEXT_INVALID("2019020700 1 2 DEADBEEF"),
		/* Digest too short */
		TEXT_INVALID("2019020700 1 3 DEADBEEFDEADBEEFDEADBE"),
		/* Digest type unknown */
		TEXT_VALID("2019020700 1 3 DEADBEEFDEADBEEFDEADBEEF"),
		/* Digest type max */
		TEXT_VALID("2019020700 1 255 DEADBEEFDEADBEEFDEADBEEF"),
		/* Digest type too big */
		TEXT_INVALID("2019020700 0 256 DEADBEEFDEADBEEFDEADBEEF"),
		/* Scheme max */
		TEXT_VALID("2019020700 255 3 DEADBEEFDEADBEEFDEADBEEF"),
		/* Scheme too big */
		TEXT_INVALID("2019020700 256 3 DEADBEEFDEADBEEFDEADBEEF"),
		/* SHA384 */
		TEXT_VALID("2019020700 1 1 "
			   "7162D2BB75C047A53DE98767C9192BEB"
			   "14DB01E7E2267135DAF0230A 19BA4A31"
			   "6AF6BF64AA5C7BAE24B2992850300509"),
		/* SHA512 */
		TEXT_VALID("2019020700 1 2 "
			   "08CFA1115C7B948C4163A901270395EA"
			   "226A930CD2CBCF2FA9A5E6EB 85F37C8A"
			   "4E114D884E66F176EAB121CB02DB7D65"
			   "2E0CC4827E7A3204 F166B47E5613FD27"),
		/* SHA384 too short and with private scheme */
		TEXT_INVALID("2021042801 0 1 "
			     "7162D2BB75C047A53DE98767C9192BEB"
			     "6AF6BF64AA5C7BAE24B2992850300509"),
		/* SHA512 too short and with private scheme */
		TEXT_INVALID("2021042802 5 2 "
			     "A897B40072ECAE9E4CA3F1F227DE8F5E"
			     "480CDEBB16DFC64C1C349A7B5F6C71AB"
			     "E8A88B76EF0BA1604EC25752E946BF98"),
		TEXT_SENTINEL()
	};
	wire_ok_t wire_ok[] = {
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Short.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
		/*
		 * Short 11-octet digest.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00),
		/*
		 * Minimal, 12-octet hash for an undefined digest type.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			   0x00),
		/*
		 * SHA-384 is defined, so we insist there be a digest of
		 * the expected length.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00),
		/*
		 * 48-octet digest, valid for SHA-384.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			   0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			   0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa,
			   0xce),
		/*
		 * 56-octet digest, too long for SHA-384.
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
			     0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			     0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
			     0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			     0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce),
		/*
		 * 56-octet digest, too short for SHA-512
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
			     0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			     0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
			     0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			     0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad),
		/*
		 * 64-octet digest, just right for SHA-512
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			   0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			   0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			   0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef),
		/*
		 * 72-octet digest, too long for SHA-512
		 */
		WIRE_INVALID(0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
			     0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			     0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
			     0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			     0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad,
			     0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
			     0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			     0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce),
		/*
		 * 56-octet digest, valid for an undefined digest type.
		 */
		WIRE_VALID(0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			   0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			   0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe,
			   0xef, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce,
			   0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce),
		/*
		 * Sentinel.
		 */
		WIRE_SENTINEL()
	};

	check_rdata(text_ok, wire_ok, NULL, false, dns_rdataclass_in,
		    dns_rdatatype_zonemd, sizeof(dns_rdata_zonemd_t));
}

ISC_RUN_TEST_IMPL(atcname) {
	unsigned int i;

#define UNR "# Unexpected result from dns_rdatatype_atcname for type %u\n"
	for (i = 0; i < 0xffffU; i++) {
		bool tf = dns_rdatatype_atcname((dns_rdatatype_t)i);
		switch (i) {
		case dns_rdatatype_nsec:
		case dns_rdatatype_key:
		case dns_rdatatype_rrsig:
			if (!tf) {
				print_message(UNR, i);
			}
			assert_true(tf);
			break;
		default:
			if (tf) {
				print_message(UNR, i);
			}
			assert_false(tf);
			break;
		}
	}
#undef UNR
}

ISC_RUN_TEST_IMPL(atparent) {
	unsigned int i;

#define UNR "# Unexpected result from dns_rdatatype_atparent for type %u\n"
	for (i = 0; i < 0xffffU; i++) {
		bool tf = dns_rdatatype_atparent((dns_rdatatype_t)i);
		switch (i) {
		case dns_rdatatype_ds:
			if (!tf) {
				print_message(UNR, i);
			}
			assert_true(tf);
			break;
		default:
			if (tf) {
				print_message(UNR, i);
			}
			assert_false(tf);
			break;
		}
	}
#undef UNR
}

ISC_RUN_TEST_IMPL(iszonecutauth) {
	unsigned int i;
#define UNR "# Unexpected result from dns_rdatatype_iszonecutauth for type %u\n"
	for (i = 0; i < 0xffffU; i++) {
		bool tf = dns_rdatatype_iszonecutauth((dns_rdatatype_t)i);
		switch (i) {
		case dns_rdatatype_ns:
		case dns_rdatatype_ds:
		case dns_rdatatype_nsec:
		case dns_rdatatype_key:
		case dns_rdatatype_rrsig:
			if (!tf) {
				print_message(UNR, i);
			}
			assert_true(tf);
			break;
		default:
			if (tf) {
				print_message(UNR, i);
			}
			assert_false(tf);
			break;
		}
	}
#undef UNR
}

ISC_TEST_LIST_START

/* types */
ISC_TEST_ENTRY(amtrelay)
ISC_TEST_ENTRY(apl)
ISC_TEST_ENTRY(atma)
ISC_TEST_ENTRY(cdnskey)
ISC_TEST_ENTRY(csync)
ISC_TEST_ENTRY(dnskey)
ISC_TEST_ENTRY(doa)
ISC_TEST_ENTRY(ds)
ISC_TEST_ENTRY(eid)
ISC_TEST_ENTRY(hip)
ISC_TEST_ENTRY(https_svcb)
ISC_TEST_ENTRY(isdn)
ISC_TEST_ENTRY(key)
ISC_TEST_ENTRY(loc)
ISC_TEST_ENTRY(nimloc)
ISC_TEST_ENTRY(nsec)
ISC_TEST_ENTRY(nsec3)
ISC_TEST_ENTRY(nxt)
ISC_TEST_ENTRY(rkey)
ISC_TEST_ENTRY(resinfo)
ISC_TEST_ENTRY(sshfp)
ISC_TEST_ENTRY(wallet)
ISC_TEST_ENTRY(wks)
ISC_TEST_ENTRY(zonemd)

/* other tests */
ISC_TEST_ENTRY(edns_client_subnet)
ISC_TEST_ENTRY(atcname)
ISC_TEST_ENTRY(atparent)
ISC_TEST_ENTRY(iszonecutauth)
ISC_TEST_LIST_END

ISC_TEST_MAIN
