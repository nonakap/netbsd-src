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
        "*.new",
        "*.signed",
        "K*",
        "dsset-*",
        "inact.key",
        "keys",
        "ksk.key",
        "oldstyle.key",
        "parent.ksk.key",
        "parent.zsk.key",
        "pending.key",
        "postrev.key",
        "prerev.key",
        "rolling.key",
        "settime*.test*",
        "sigs",
        "standby.key",
        "tmp.out",
        "zsk.key",
    ]
)


def test_metadata(run_tests_sh):
    run_tests_sh()
