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

import pytest

pytestmark = pytest.mark.extra_artifacts(
    [
        "dig.out.*",
        "ns2/K*",
        "ns2/db.*",
        "ns2/*.jnl",
        "ns2/example.db",
        "ns2/zones.conf",
        "ns2/external/K*",
        "ns2/external/inline.db.jbk",
        "ns2/external/inline.db.signed",
        "ns2/external/inline.db.signed.jnl",
        "ns2/internal/K*",
        "ns2/internal/inline.db.jbk",
        "ns2/internal/inline.db.signed",
        "ns2/internal/inline.db.signed.jnl",
        "ns3/internal.bk",
    ]
)


def test_views(run_tests_sh):
    run_tests_sh()
