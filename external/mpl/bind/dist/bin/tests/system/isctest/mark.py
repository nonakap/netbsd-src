#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import os
from pathlib import Path
import subprocess

import pytest


long_test = pytest.mark.skipif(
    not os.environ.get("CI_ENABLE_ALL_TESTS"), reason="CI_ENABLE_ALL_TESTS not set"
)


def feature_test(feature):
    feature_test_bin = os.environ["FEATURETEST"]
    try:
        subprocess.run([feature_test_bin, feature], check=True)
    except subprocess.CalledProcessError as exc:
        if exc.returncode != 1:
            raise
        return False
    return True


DNSRPS_BIN = Path(os.environ["TOP_BUILDDIR"]) / "bin/tests/system/rpz/dnsrps"


def is_dnsrps_available():
    if not feature_test("--enable-dnsrps"):
        return False
    try:
        subprocess.run([DNSRPS_BIN, "-a"], check=True)
    except subprocess.CalledProcessError:
        return False
    return True


def with_dnstap(*args):  # pylint: disable=unused-argument
    return feature_test("--enable-dnstap")


def with_tsan(*args):  # pylint: disable=unused-argument
    return feature_test("--tsan")


have_libxml2 = pytest.mark.skipif(
    not feature_test("--have-libxml2"), reason="libxml2 support disabled in the build"
)

have_json_c = pytest.mark.skipif(
    not feature_test("--have-json-c"), reason="json-c support disabled in the build"
)

dnsrps_enabled = pytest.mark.skipif(
    not is_dnsrps_available(), reason="dnsrps disabled in the build"
)


try:
    import flaky as flaky_pkg  # type: ignore
except ModuleNotFoundError:
    # In case the flaky package is not installed, run the tests as usual
    # without any attempts to re-run them.
    # pylint: disable=unused-argument
    def flaky(*args, **kwargs):
        """Mock decorator that doesn't do anything special, just returns the function."""

        def wrapper(wrapped_obj):
            return wrapped_obj

        return wrapper

else:
    flaky = flaky_pkg.flaky
