/*	$NetBSD: named-checkconf.c,v 1.13 2025/05/21 14:47:34 christos Exp $	*/

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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <isc/attributes.h>
#include <isc/commandline.h>
#include <isc/dir.h>
#include <isc/hash.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/log.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/rootns.h>
#include <dns/zone.h>

#include <isccfg/check.h>
#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

#include "check-tool.h"

static const char *program = "named-checkconf";

isc_log_t *logc = NULL;

#define CHECK(r)                             \
	do {                                 \
		result = (r);                \
		if (result != ISC_R_SUCCESS) \
			goto cleanup;        \
	} while (0)

/*% usage */
noreturn static void
usage(void);

static void
usage(void) {
	fprintf(stderr,
		"usage: %s [-achijlvz] [-p [-x]] [-t directory] "
		"[named.conf]\n",
		program);
	exit(EXIT_SUCCESS);
}

/*% directory callback */
static isc_result_t
directory_callback(const char *clausename, const cfg_obj_t *obj, void *arg) {
	isc_result_t result;
	const char *directory;

	REQUIRE(strcasecmp("directory", clausename) == 0);

	UNUSED(arg);
	UNUSED(clausename);

	/*
	 * Change directory.
	 */
	directory = cfg_obj_asstring(obj);
	result = isc_dir_chdir(directory);
	if (result != ISC_R_SUCCESS) {
		cfg_obj_log(obj, logc, ISC_LOG_ERROR,
			    "change directory to '%s' failed: %s\n", directory,
			    isc_result_totext(result));
		return result;
	}

	return ISC_R_SUCCESS;
}

static bool
get_maps(const cfg_obj_t **maps, const char *name, const cfg_obj_t **obj) {
	int i;
	for (i = 0;; i++) {
		if (maps[i] == NULL) {
			return false;
		}
		if (cfg_map_get(maps[i], name, obj) == ISC_R_SUCCESS) {
			return true;
		}
	}
}

static bool
get_checknames(const cfg_obj_t **maps, const cfg_obj_t **obj) {
	const cfg_listelt_t *element;
	const cfg_obj_t *checknames;
	const cfg_obj_t *type;
	const cfg_obj_t *value;
	isc_result_t result;
	int i;

	for (i = 0;; i++) {
		if (maps[i] == NULL) {
			return false;
		}
		checknames = NULL;
		result = cfg_map_get(maps[i], "check-names", &checknames);
		if (result != ISC_R_SUCCESS) {
			continue;
		}
		if (checknames != NULL && !cfg_obj_islist(checknames)) {
			*obj = checknames;
			return true;
		}
		for (element = cfg_list_first(checknames); element != NULL;
		     element = cfg_list_next(element))
		{
			value = cfg_listelt_value(element);
			type = cfg_tuple_get(value, "type");
			if ((strcasecmp(cfg_obj_asstring(type), "primary") !=
			     0) &&
			    (strcasecmp(cfg_obj_asstring(type), "master") != 0))
			{
				continue;
			}
			*obj = cfg_tuple_get(value, "mode");
			return true;
		}
	}
}

static isc_result_t
configure_hint(const char *zfile, const char *zclass, isc_mem_t *mctx) {
	isc_result_t result;
	dns_db_t *db = NULL;
	dns_rdataclass_t rdclass;
	isc_textregion_t r;

	if (zfile == NULL) {
		return ISC_R_FAILURE;
	}

	r.base = UNCONST(zclass);
	r.length = strlen(zclass);
	result = dns_rdataclass_fromtext(&rdclass, &r);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = dns_rootns_create(mctx, rdclass, zfile, &db);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	dns_db_detach(&db);
	return ISC_R_SUCCESS;
}

/*% configure the zone */
static isc_result_t
configure_zone(const char *vclass, const char *view, const cfg_obj_t *zconfig,
	       const cfg_obj_t *vconfig, const cfg_obj_t *config,
	       isc_mem_t *mctx, bool list) {
	int i = 0;
	isc_result_t result;
	const char *zclass;
	const char *zname;
	const char *zfile = NULL;
	const cfg_obj_t *maps[4];
	const cfg_obj_t *primariesobj = NULL;
	const cfg_obj_t *inviewobj = NULL;
	const cfg_obj_t *zoptions = NULL;
	const cfg_obj_t *classobj = NULL;
	const cfg_obj_t *typeobj = NULL;
	const cfg_obj_t *fileobj = NULL;
	const cfg_obj_t *dlzobj = NULL;
	const cfg_obj_t *dbobj = NULL;
	const cfg_obj_t *obj = NULL;
	const cfg_obj_t *fmtobj = NULL;
	dns_masterformat_t masterformat;
	dns_ttl_t maxttl = 0;

	zone_options = DNS_ZONEOPT_CHECKNS | DNS_ZONEOPT_MANYERRORS;

	zname = cfg_obj_asstring(cfg_tuple_get(zconfig, "name"));
	classobj = cfg_tuple_get(zconfig, "class");
	if (!cfg_obj_isstring(classobj)) {
		zclass = vclass;
	} else {
		zclass = cfg_obj_asstring(classobj);
	}

	zoptions = cfg_tuple_get(zconfig, "options");
	maps[i++] = zoptions;
	if (vconfig != NULL) {
		maps[i++] = cfg_tuple_get(vconfig, "options");
	}
	if (config != NULL) {
		cfg_map_get(config, "options", &obj);
		if (obj != NULL) {
			maps[i++] = obj;
		}
	}
	maps[i] = NULL;

	cfg_map_get(zoptions, "in-view", &inviewobj);
	if (inviewobj != NULL && list) {
		const char *inview = cfg_obj_asstring(inviewobj);
		printf("%s %s %s in-view %s\n", zname, zclass, view, inview);
	}
	if (inviewobj != NULL) {
		return ISC_R_SUCCESS;
	}

	cfg_map_get(zoptions, "type", &typeobj);
	if (typeobj == NULL) {
		return ISC_R_FAILURE;
	}

	if (list) {
		const char *ztype = cfg_obj_asstring(typeobj);
		printf("%s %s %s %s\n", zname, zclass, view, ztype);
		return ISC_R_SUCCESS;
	}

	/*
	 * Skip checks when using an alternate data source.
	 */
	cfg_map_get(zoptions, "database", &dbobj);
	if (dbobj != NULL &&
	    strcmp(ZONEDB_DEFAULT, cfg_obj_asstring(dbobj)) != 0)
	{
		return ISC_R_SUCCESS;
	}

	cfg_map_get(zoptions, "dlz", &dlzobj);
	if (dlzobj != NULL) {
		return ISC_R_SUCCESS;
	}

	cfg_map_get(zoptions, "file", &fileobj);
	if (fileobj != NULL) {
		zfile = cfg_obj_asstring(fileobj);
	}

	/*
	 * Check hints files for hint zones.
	 * Skip loading checks for any type other than
	 * master and redirect
	 */
	if (strcasecmp(cfg_obj_asstring(typeobj), "hint") == 0) {
		return configure_hint(zfile, zclass, mctx);
	} else if ((strcasecmp(cfg_obj_asstring(typeobj), "primary") != 0) &&
		   (strcasecmp(cfg_obj_asstring(typeobj), "master") != 0) &&
		   (strcasecmp(cfg_obj_asstring(typeobj), "redirect") != 0))
	{
		return ISC_R_SUCCESS;
	}

	/*
	 * Is the redirect zone configured as a secondary?
	 */
	if (strcasecmp(cfg_obj_asstring(typeobj), "redirect") == 0) {
		cfg_map_get(zoptions, "primaries", &primariesobj);
		if (primariesobj == NULL) {
			cfg_map_get(zoptions, "masters", &primariesobj);
		}

		if (primariesobj != NULL) {
			return ISC_R_SUCCESS;
		}
	}

	if (zfile == NULL) {
		return ISC_R_FAILURE;
	}

	obj = NULL;
	if (get_maps(maps, "check-dup-records", &obj)) {
		if (strcasecmp(cfg_obj_asstring(obj), "warn") == 0) {
			zone_options |= DNS_ZONEOPT_CHECKDUPRR;
			zone_options &= ~DNS_ZONEOPT_CHECKDUPRRFAIL;
		} else if (strcasecmp(cfg_obj_asstring(obj), "fail") == 0) {
			zone_options |= DNS_ZONEOPT_CHECKDUPRR;
			zone_options |= DNS_ZONEOPT_CHECKDUPRRFAIL;
		} else if (strcasecmp(cfg_obj_asstring(obj), "ignore") == 0) {
			zone_options &= ~DNS_ZONEOPT_CHECKDUPRR;
			zone_options &= ~DNS_ZONEOPT_CHECKDUPRRFAIL;
		} else {
			UNREACHABLE();
		}
	} else {
		zone_options |= DNS_ZONEOPT_CHECKDUPRR;
		zone_options &= ~DNS_ZONEOPT_CHECKDUPRRFAIL;
	}

	obj = NULL;
	if (get_maps(maps, "check-mx", &obj)) {
		if (strcasecmp(cfg_obj_asstring(obj), "warn") == 0) {
			zone_options |= DNS_ZONEOPT_CHECKMX;
			zone_options &= ~DNS_ZONEOPT_CHECKMXFAIL;
		} else if (strcasecmp(cfg_obj_asstring(obj), "fail") == 0) {
			zone_options |= DNS_ZONEOPT_CHECKMX;
			zone_options |= DNS_ZONEOPT_CHECKMXFAIL;
		} else if (strcasecmp(cfg_obj_asstring(obj), "ignore") == 0) {
			zone_options &= ~DNS_ZONEOPT_CHECKMX;
			zone_options &= ~DNS_ZONEOPT_CHECKMXFAIL;
		} else {
			UNREACHABLE();
		}
	} else {
		zone_options |= DNS_ZONEOPT_CHECKMX;
		zone_options &= ~DNS_ZONEOPT_CHECKMXFAIL;
	}

	obj = NULL;
	if (get_maps(maps, "check-integrity", &obj)) {
		if (cfg_obj_asboolean(obj)) {
			zone_options |= DNS_ZONEOPT_CHECKINTEGRITY;
		} else {
			zone_options &= ~DNS_ZONEOPT_CHECKINTEGRITY;
		}
	} else {
		zone_options |= DNS_ZONEOPT_CHECKINTEGRITY;
	}

	obj = NULL;
	if (get_maps(maps, "check-mx-cname", &obj)) {
		if (strcasecmp(cfg_obj_asstring(obj), "warn") == 0) {
			zone_options |= DNS_ZONEOPT_WARNMXCNAME;
			zone_options &= ~DNS_ZONEOPT_IGNOREMXCNAME;
		} else if (strcasecmp(cfg_obj_asstring(obj), "fail") == 0) {
			zone_options &= ~DNS_ZONEOPT_WARNMXCNAME;
			zone_options &= ~DNS_ZONEOPT_IGNOREMXCNAME;
		} else if (strcasecmp(cfg_obj_asstring(obj), "ignore") == 0) {
			zone_options |= DNS_ZONEOPT_WARNMXCNAME;
			zone_options |= DNS_ZONEOPT_IGNOREMXCNAME;
		} else {
			UNREACHABLE();
		}
	} else {
		zone_options |= DNS_ZONEOPT_WARNMXCNAME;
		zone_options &= ~DNS_ZONEOPT_IGNOREMXCNAME;
	}

	obj = NULL;
	if (get_maps(maps, "check-srv-cname", &obj)) {
		if (strcasecmp(cfg_obj_asstring(obj), "warn") == 0) {
			zone_options |= DNS_ZONEOPT_WARNSRVCNAME;
			zone_options &= ~DNS_ZONEOPT_IGNORESRVCNAME;
		} else if (strcasecmp(cfg_obj_asstring(obj), "fail") == 0) {
			zone_options &= ~DNS_ZONEOPT_WARNSRVCNAME;
			zone_options &= ~DNS_ZONEOPT_IGNORESRVCNAME;
		} else if (strcasecmp(cfg_obj_asstring(obj), "ignore") == 0) {
			zone_options |= DNS_ZONEOPT_WARNSRVCNAME;
			zone_options |= DNS_ZONEOPT_IGNORESRVCNAME;
		} else {
			UNREACHABLE();
		}
	} else {
		zone_options |= DNS_ZONEOPT_WARNSRVCNAME;
		zone_options &= ~DNS_ZONEOPT_IGNORESRVCNAME;
	}

	obj = NULL;
	if (get_maps(maps, "check-sibling", &obj)) {
		if (cfg_obj_asboolean(obj)) {
			zone_options |= DNS_ZONEOPT_CHECKSIBLING;
		} else {
			zone_options &= ~DNS_ZONEOPT_CHECKSIBLING;
		}
	}

	obj = NULL;
	if (get_maps(maps, "check-spf", &obj)) {
		if (strcasecmp(cfg_obj_asstring(obj), "warn") == 0) {
			zone_options |= DNS_ZONEOPT_CHECKSPF;
		} else if (strcasecmp(cfg_obj_asstring(obj), "ignore") == 0) {
			zone_options &= ~DNS_ZONEOPT_CHECKSPF;
		} else {
			UNREACHABLE();
		}
	} else {
		zone_options |= DNS_ZONEOPT_CHECKSPF;
	}

	obj = NULL;
	if (get_maps(maps, "check-svcb", &obj)) {
		if (cfg_obj_asboolean(obj)) {
			zone_options |= DNS_ZONEOPT_CHECKSVCB;
		} else {
			zone_options &= ~DNS_ZONEOPT_CHECKSVCB;
		}
	} else {
		zone_options |= DNS_ZONEOPT_CHECKSVCB;
	}

	obj = NULL;
	if (get_maps(maps, "check-wildcard", &obj)) {
		if (cfg_obj_asboolean(obj)) {
			zone_options |= DNS_ZONEOPT_CHECKWILDCARD;
		} else {
			zone_options &= ~DNS_ZONEOPT_CHECKWILDCARD;
		}
	} else {
		zone_options |= DNS_ZONEOPT_CHECKWILDCARD;
	}

	obj = NULL;
	if (get_checknames(maps, &obj)) {
		if (strcasecmp(cfg_obj_asstring(obj), "warn") == 0) {
			zone_options |= DNS_ZONEOPT_CHECKNAMES;
			zone_options &= ~DNS_ZONEOPT_CHECKNAMESFAIL;
		} else if (strcasecmp(cfg_obj_asstring(obj), "fail") == 0) {
			zone_options |= DNS_ZONEOPT_CHECKNAMES;
			zone_options |= DNS_ZONEOPT_CHECKNAMESFAIL;
		} else if (strcasecmp(cfg_obj_asstring(obj), "ignore") == 0) {
			zone_options &= ~DNS_ZONEOPT_CHECKNAMES;
			zone_options &= ~DNS_ZONEOPT_CHECKNAMESFAIL;
		} else {
			UNREACHABLE();
		}
	} else {
		zone_options |= DNS_ZONEOPT_CHECKNAMES;
		zone_options |= DNS_ZONEOPT_CHECKNAMESFAIL;
	}

	masterformat = dns_masterformat_text;
	fmtobj = NULL;
	if (get_maps(maps, "masterfile-format", &fmtobj)) {
		const char *masterformatstr = cfg_obj_asstring(fmtobj);
		if (strcasecmp(masterformatstr, "text") == 0) {
			masterformat = dns_masterformat_text;
		} else if (strcasecmp(masterformatstr, "raw") == 0) {
			masterformat = dns_masterformat_raw;
		} else {
			UNREACHABLE();
		}
	}

	obj = NULL;
	if (get_maps(maps, "max-zone-ttl", &obj)) {
		maxttl = cfg_obj_asduration(obj);
		zone_options |= DNS_ZONEOPT_CHECKTTL;
	}

	result = load_zone(mctx, zname, zfile, masterformat, zclass, maxttl,
			   NULL);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "%s/%s/%s: %s\n", view, zname, zclass,
			isc_result_totext(result));
	}
	return result;
}

/*% configure a view */
static isc_result_t
configure_view(const char *vclass, const char *view, const cfg_obj_t *config,
	       const cfg_obj_t *vconfig, isc_mem_t *mctx, bool list) {
	const cfg_listelt_t *element;
	const cfg_obj_t *voptions;
	const cfg_obj_t *zonelist;
	isc_result_t result = ISC_R_SUCCESS;
	isc_result_t tresult;

	voptions = NULL;
	if (vconfig != NULL) {
		voptions = cfg_tuple_get(vconfig, "options");
	}

	zonelist = NULL;
	if (voptions != NULL) {
		(void)cfg_map_get(voptions, "zone", &zonelist);
	} else {
		(void)cfg_map_get(config, "zone", &zonelist);
	}

	for (element = cfg_list_first(zonelist); element != NULL;
	     element = cfg_list_next(element))
	{
		const cfg_obj_t *zconfig = cfg_listelt_value(element);
		tresult = configure_zone(vclass, view, zconfig, vconfig, config,
					 mctx, list);
		if (tresult != ISC_R_SUCCESS) {
			result = tresult;
		}
	}
	return result;
}

static isc_result_t
config_getclass(const cfg_obj_t *classobj, dns_rdataclass_t defclass,
		dns_rdataclass_t *classp) {
	isc_textregion_t r;

	if (!cfg_obj_isstring(classobj)) {
		*classp = defclass;
		return ISC_R_SUCCESS;
	}
	r.base = UNCONST(cfg_obj_asstring(classobj));
	r.length = strlen(r.base);
	return dns_rdataclass_fromtext(classp, &r);
}

/*% load zones from the configuration */
static isc_result_t
load_zones_fromconfig(const cfg_obj_t *config, isc_mem_t *mctx,
		      bool list_zones) {
	const cfg_listelt_t *element;
	const cfg_obj_t *views;
	const cfg_obj_t *vconfig;
	isc_result_t result = ISC_R_SUCCESS;
	isc_result_t tresult;

	views = NULL;

	(void)cfg_map_get(config, "view", &views);
	for (element = cfg_list_first(views); element != NULL;
	     element = cfg_list_next(element))
	{
		const cfg_obj_t *classobj;
		dns_rdataclass_t viewclass;
		const char *vname;
		char buf[sizeof("CLASS65535")];

		vconfig = cfg_listelt_value(element);
		if (vconfig == NULL) {
			continue;
		}

		classobj = cfg_tuple_get(vconfig, "class");
		tresult = config_getclass(classobj, dns_rdataclass_in,
					  &viewclass);
		if (tresult != ISC_R_SUCCESS) {
			CHECK(tresult);
		}

		if (dns_rdataclass_ismeta(viewclass)) {
			CHECK(ISC_R_FAILURE);
		}

		dns_rdataclass_format(viewclass, buf, sizeof(buf));
		vname = cfg_obj_asstring(cfg_tuple_get(vconfig, "name"));
		tresult = configure_view(buf, vname, config, vconfig, mctx,
					 list_zones);
		if (tresult != ISC_R_SUCCESS) {
			result = tresult;
		}
	}

	if (views == NULL) {
		tresult = configure_view("IN", "_default", config, NULL, mctx,
					 list_zones);
		if (tresult != ISC_R_SUCCESS) {
			result = tresult;
		}
	}

cleanup:
	return result;
}

static void
output(void *closure, const char *text, int textlen) {
	if (fwrite(text, 1, textlen, stdout) != (size_t)textlen) {
		isc_result_t *result = closure;
		perror("fwrite");
		*result = ISC_R_FAILURE;
	}
}

/*% The main processing routine */
int
main(int argc, char **argv) {
	int c;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *config = NULL;
	const char *conffile = NULL;
	isc_mem_t *mctx = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	bool cleanup_dst = false;
	bool load_zones = false;
	bool list_zones = false;
	bool print = false;
	bool nodeprecate = false;
	unsigned int flags = 0;
	unsigned int checkflags = BIND_CHECK_PLUGINS | BIND_CHECK_ALGORITHMS;

	isc_commandline_errprint = false;

	/*
	 * Process memory debugging argument first.
	 */
#define CMDLINE_FLAGS "acdhijlm:t:pvxz"
	while ((c = isc_commandline_parse(argc, argv, CMDLINE_FLAGS)) != -1) {
		switch (c) {
		case 'm':
			if (strcasecmp(isc_commandline_argument, "record") == 0)
			{
				isc_mem_debugging |= ISC_MEM_DEBUGRECORD;
			}
			if (strcasecmp(isc_commandline_argument, "trace") == 0)
			{
				isc_mem_debugging |= ISC_MEM_DEBUGTRACE;
			}
			if (strcasecmp(isc_commandline_argument, "usage") == 0)
			{
				isc_mem_debugging |= ISC_MEM_DEBUGUSAGE;
			}
			break;
		default:
			break;
		}
	}
	isc_commandline_reset = true;

	isc_mem_create(&mctx);

	while ((c = isc_commandline_parse(argc, argv, CMDLINE_FLAGS)) != EOF) {
		switch (c) {
		case 'a':
			checkflags &= ~BIND_CHECK_ALGORITHMS;
			break;

		case 'c':
			checkflags &= ~BIND_CHECK_PLUGINS;
			break;

		case 'd':
			debug++;
			break;

		case 'i':
			nodeprecate = true;
			break;

		case 'j':
			nomerge = false;
			break;

		case 'l':
			list_zones = true;
			break;

		case 'm':
			break;

		case 't':
			result = isc_dir_chroot(isc_commandline_argument);
			if (result != ISC_R_SUCCESS) {
				fprintf(stderr, "isc_dir_chroot: %s\n",
					isc_result_totext(result));
				CHECK(result);
			}
			break;

		case 'p':
			print = true;
			break;

		case 'v':
			printf("%s\n", PACKAGE_VERSION);
			result = ISC_R_SUCCESS;
			goto cleanup;

		case 'x':
			flags |= CFG_PRINTER_XKEY;
			break;

		case 'z':
			load_zones = true;
			docheckmx = false;
			docheckns = false;
			dochecksrv = false;
			break;

		case '?':
			if (isc_commandline_option != '?') {
				fprintf(stderr, "%s: invalid argument -%c\n",
					program, isc_commandline_option);
			}
			FALLTHROUGH;
		case 'h':
			isc_mem_detach(&mctx);
			usage();

		default:
			fprintf(stderr, "%s: unhandled option -%c\n", program,
				isc_commandline_option);
			CHECK(ISC_R_FAILURE);
		}
	}

	if (((flags & CFG_PRINTER_XKEY) != 0) && !print) {
		fprintf(stderr, "%s: -x cannot be used without -p\n", program);
		CHECK(ISC_R_FAILURE);
	}
	if (print && list_zones) {
		fprintf(stderr, "%s: -l cannot be used with -p\n", program);
		CHECK(ISC_R_FAILURE);
	}

	if (isc_commandline_index + 1 < argc) {
		isc_mem_detach(&mctx);
		usage();
	}
	if (argv[isc_commandline_index] != NULL) {
		conffile = argv[isc_commandline_index];
	}
	if (conffile == NULL || conffile[0] == '\0') {
		conffile = NAMED_CONFFILE;
	}

	CHECK(setup_logging(mctx, stdout, &logc));

	CHECK(dst_lib_init(mctx, NULL));
	cleanup_dst = true;

	CHECK(cfg_parser_create(mctx, logc, &parser));

	if (nodeprecate) {
		cfg_parser_setflags(parser, CFG_PCTX_NODEPRECATED, true);
	}
	cfg_parser_setcallback(parser, directory_callback, NULL);

	CHECK(cfg_parse_file(parser, conffile, &cfg_type_namedconf, &config));
	CHECK(isccfg_check_namedconf(config, checkflags, logc, mctx));
	if (load_zones || list_zones) {
		CHECK(load_zones_fromconfig(config, mctx, list_zones));
	}

	if (print) {
		cfg_printx(config, flags, output, &result);
	}

cleanup:
	if (config != NULL) {
		cfg_obj_destroy(parser, &config);
	}

	if (parser != NULL) {
		cfg_parser_destroy(&parser);
	}

	if (cleanup_dst) {
		dst_lib_destroy();
	}

	/*
	 * Wait for memory reclamation in dns_qp to finish.
	 */
	rcu_barrier();

	if (logc != NULL) {
		isc_log_destroy(&logc);
	}

	if (mctx != NULL) {
		isc_mem_destroy(&mctx);
	}

	return result == ISC_R_SUCCESS ? 0 : 1;
}
