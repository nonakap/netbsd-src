.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

.. _dnssec:

DNSSEC
------
DNS Security Extensions (DNSSEC) provide reliable protection from
`cache poisoning`_ attacks. At the same time these extensions also provide other benefits:
they limit the impact of `random subdomain attacks`_ on resolver caches and authoritative
servers, and provide the foundation for modern applications like `authenticated
and private e-mail transfer`_.

To achieve this goal, DNSSEC adds `digital signatures`_ to DNS records in
authoritative DNS zones, and DNS resolvers verify the validity of the signatures on the
received records. If the signatures match the received data, the resolver can
be sure that the data was not modified in transit.

.. note::
   DNSSEC and transport-level encryption are complementary!
   Unlike typical transport-level encryption like DNS-over-TLS, DNS-over-HTTPS,
   or VPN, DNSSEC makes DNS records verifiable at all points of the DNS
   resolution chain.

This section focuses on ways to deploy DNSSEC using BIND. For a more in-depth
discussion of DNSSEC principles (e.g. :ref:`how_does_dnssec_change_dns_lookup`)
please see :doc:`dnssec-guide`.

.. _`cache poisoning`: https://en.wikipedia.org/wiki/DNS_cache_poisoning
.. _`random subdomain attacks`: https://www.isc.org/blogs/nsec-caching-should-limit-excessive-queries-to-dns-root/
.. _`digital signatures`: https://en.wikipedia.org/wiki/Digital_signature
.. _`authenticated and private e-mail transfer`: https://github.com/internetstandards/toolbox-wiki/blob/main/DANE-for-SMTP-how-to.md


.. _dnssec_zone_signing:

Zone Signing
~~~~~~~~~~~~

BIND offers several ways to generate signatures and maintain their validity
during the lifetime of a DNS zone:

  - :ref:`dnssec_kasp` - **strongly recommended**
  - :ref:`dnssec_tools` - discouraged, use only for debugging

.. _zone_keys:

Zone keys
^^^^^^^^^
Regardless of the :ref:`zone-signing <dnssec_zone_signing>` method in use, cryptographic keys are
stored in files named like :file:`Kdnssec.example.+013+12345.key` and
:file:`Kdnssec.example.+013+12345.private`.
The private key (in the ``.private`` file) is used to generate signatures, and
the public key (in the ``.key`` file) is used for signature verification.
Additionally, the :ref:`dnssec_kasp` method creates a third file,
:file:`Kdnssec.example+013+12345.state`, which is used to track DNSSEC key timings
and to perform key rollovers safely.

These filenames contain:

   - the key name, which always matches the zone name (``dnssec.example.``),
   - the `algorithm number`_ (013 is ECDSAP256SHA256, 008 is RSASHA256, etc.),
   - and the key tag, i.e. a non-unique key identifier (12345 in this case).

.. _`algorithm number`: https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1


.. warning::
   Private keys are required for full disaster recovery. Back up key files in a
   safe location and protect them from unauthorized access. Anyone with
   access to the private key can create fake but seemingly valid DNS data.


.. _dnssec_kasp:

Fully Automated (Key and Signing Policy)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Key and Signing Policy (KASP) is a method of configuration that describes
how to maintain DNSSEC signing keys and how to sign the zone.

This is the recommended, fully automated way to sign and maintain DNS zones. For
most use cases users can simply use the built-in default policy, which applies
up-to-date DNSSEC practices:

.. code-block:: none
  :emphasize-lines: 4

    zone "dnssec.example" {
        type primary;
        file "dnssec.example.db";
        dnssec-policy default;
    };

The :any:`dnssec-policy` statement requires dynamic DNS to be set up, or
:any:`inline-signing` to be enabled. In the example above we use the latter,
because the ``default`` policy uses :any:`inline-signing`.

This is sufficient to create the necessary signing keys, and generate
``DNSKEY``, ``RRSIG``, and ``NSEC`` records for the zone. BIND also takes
care of any DNSSEC maintenance for this zone, including replacing signatures
that are about to expire and managing :ref:`key_rollovers`.

.. note::
   :any:`dnssec-policy` needs write access to the zone. Please see
   :any:`dnssec-policy` for more details about implications for zone storage.

The default policy creates one key that is used to sign the complete zone,
and uses ``NSEC`` to enable authenticated denial of existence (a secure way
to tell which records do not exist in a zone). This policy is recommended
and typically does not need to be changed.

If needed, a custom policy can be defined by adding a :any:`dnssec-policy` statement
into the configuration:

.. code-block:: none


    dnssec-policy "custom" {
        dnskey-ttl 600;
        keys {
            ksk lifetime P1Y algorithm ecdsap384sha384;
            zsk lifetime 60d algorithm ecdsap384sha384;
        };
        nsec3param iterations 0 optout no salt-length 0;
    };

This ``custom`` policy, for example:

  - uses a very short ``DNSKEY`` TTL (600 seconds),
  - uses two keys to sign the zone: a Key Signing Key (KSK) to sign the key
    related RRsets (``DNSKEY``, ``CDS``, and ``CDNSKEY``), and a Zone Signing
    Key (ZSK) to sign the rest of the zone. The KSK is automatically
    rotated after one year and the ZSK after 60 days.

Also:
  - The configured keys have a lifetime set and use the ECDSAP384SHA384
    algorithm.
  - The last line instructs BIND to generate NSEC3 records for
    :ref:`Proof of Non-Existence <advanced_discussions_proof_of_nonexistence>`,
    using zero extra iterations and no salt. NSEC3 opt-out is disabled, meaning
    insecure delegations also get an NSEC3 record.

For more information about KASP configuration see :any:`dnssec-policy`.

The :ref:`dnssec_advanced_discussions` section in the DNSSEC Guide discusses the
various policy settings and may be useful for determining values for specific
needs.

Key Rollover
============

When using a :any:`dnssec-policy`, a key lifetime can be set to trigger
key rollovers. ZSK rollovers are fully automatic, but for KSK and CSK rollovers
a DS record needs to be submitted to the parent. See
:ref:`secure_delegation` for possible ways to do so.

Once the DS is in the parent (and the DS of the predecessor key is withdrawn),
BIND needs to be told that this event has happened. This can be done automatically
by configuring parental agents:

.. code-block:: none
  :emphasize-lines: 5

    zone "dnssec.example" {
        type primary;
        file "dnssec.example.db";
        dnssec-policy default;
        parental-agents { 192.0.2.1; };
        checkds explicit;
    };

Here one server, ``192.0.2.1``, is configured for BIND to send DS queries to,
to check the DS RRset for ``dnssec-example`` during key rollovers. This needs
to be a trusted server, because BIND does not validate the response. The
``checkds`` option makes BIND use the explicitly configured parental agents,
rather than looking them up by querying for the parent NS records.

If setting up a parental agent is undesirable, it is also possible to tell BIND that the
DS is published in the parent with:
:option:`rndc dnssec -checkds -key 12345 published dnssec.example. <rndc dnssec>`.
and the DS for the predecessor key has been removed with:
:option:`rndc dnssec -checkds -key 54321 withdrawn dnssec.example. <rndc dnssec>`.
where 12345 and 54321 are the key tags of the successor and predecessor key,
respectively.

To roll a key sooner than scheduled, or to roll a key that
has an unlimited lifetime, use:
:option:`rndc dnssec -rollover -key 12345 dnssec.example. <rndc dnssec>`.

You can pregenerate keys and save them in the key directory. As long as the
key has no timing metadata set, it may be selected as a successor in the
upcoming key rollover. To pregenerate keys without setting key timing metadata,
use the `-G` option: ``dnssec-keygen -G dnssec.example.``.

To revert a signed zone back to an insecure zone, change
the zone configuration to use the built-in "insecure" policy. Detailed
instructions are described in :ref:`revert_to_unsigned`.

.. _dnssec_multisigner_model:

Multi-Signer Model
==================

Dynamic zones provide the ability to sign a zone by multiple providers, meaning
each provider signs and serves the same zone independently, as is described
in :rfc:`8901`. BIND 9 is able to support Model 2, where each provider has
their own KSK and ZSK (or CSK). The keys from the other provider can be
imported via Dynamic Update. For each active KSK there must be a corresponding
DS record in the parent zone. Key rollovers require coordination in order
to update the DS and DNSKEY RRset.

.. _dnssec_tools:

Manual Signing
^^^^^^^^^^^^^^

There are several tools available to manually sign a zone.

.. warning::

   Please note manual procedures are available mainly for backwards
   compatibility and should be used only by expert users with specific needs.

To set up a DNSSEC secure zone manually, a series of steps
must be followed. Please see chapter
:ref:`advanced_discussions_manual_signing` in the
:doc:`dnssec-guide` for more information.

Monitoring with Private Type Records
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The state of the signing process is signaled by private type records (with a
default type value of 65534). When signing is complete, those records with a
non-zero initial octet have a non-zero value for the final octet.

If the first octet of a private type record is non-zero, the record indicates
either that the zone needs to be signed with the key matching the record, or
that all signatures that match the record should be removed. Here are the
meanings of the different values of the first octet:

   - algorithm (octet 1)

   - key ID in network order (octet 2 and 3)

   - removal flag (octet 4)

   - complete flag (octet 5)

Only records flagged as "complete" can be removed via dynamic update; attempts
to remove other private type records are silently ignored.

If the first octet is zero (this is a reserved algorithm number that should
never appear in a ``DNSKEY`` record), the record indicates that changes to the
``NSEC3`` chains are in progress. The rest of the record contains an
``NSEC3PARAM`` record, while the flag field tells what operation to perform
based on the flag bits:

   0x01 OPTOUT

   0x80 CREATE

   0x40 REMOVE

   0x20 NONSEC

.. _secure_delegation:

Secure Delegation
~~~~~~~~~~~~~~~~~

Once a zone is signed on the authoritative servers, the last remaining step
is to establish chain of trust [#validation]_ between the parent zone
(``example.``) and the local zone (``dnssec.example.``).

Generally the procedure is:

  - **Wait** for stale data to expire from caches. The amount of time required
    is equal to the maximum TTL value used in the zone before signing. This
    step ensures that unsigned data expire from caches and resolvers do not get
    confused by missing signatures.
  - Insert/update DS records in the parent zone (``dnssec.example. DS`` record).

There are multiple ways to update DS records in the parent zone. Refer to the
documentation for the parent zone to find out which options are applicable to
a given case zone. Generally the options are, from most- to least-recommended:

  - Automatically update the DS record in the parent zone using
    ``CDS``/``CDNSKEY`` records automatically generated by BIND. This requires
    support for :rfc:`7344` in either parent zone, registry, or registrar. In
    that case, configure BIND to :ref:`monitor DS records in the parent
    zone <cds_cdnskey>` and everything will happen automatically at the right
    time.
  - Query the zone for automatically generated ``CDS`` or ``CDNSKEY`` records using
    :iscman:`dig`, and then insert these records into the parent zone using
    the method specified by the parent zone (web form, e-mail, API, ...).
  - Generate DS records manually using the :iscman:`dnssec-dsfromkey` utility on
    `zone keys`_, and then insert them into the parent zone.

.. [#validation] For further details on how the chain of trust is used in practice, see
                :ref:`dnssec_12_steps` in the :doc:`dnssec-guide`.



DNSSEC Validation
~~~~~~~~~~~~~~~~~

The BIND resolver validates answers from authoritative servers by default. This
behavior is controlled by the configuration statement :namedconf:ref:`dnssec-validation`.

By default a trust anchor for the DNS root zone is used.
This trust anchor is provided as part of BIND and is kept up-to-date using
:ref:`rfc5011.support`.

.. note::
   DNSSEC validation works "out of the box" and does not require
   additional configuration. Additional configuration options are intended only
   for special cases.

To validate answers, the resolver needs at least one trusted starting point,
a "trust anchor." Essentially, trust anchors are copies of ``DNSKEY`` RRs for
zones that are used to form the first link in the cryptographic chain of trust.
Alternative trust anchors can be specified using :any:`trust-anchors`, but
this setup is very unusual and is recommended only for expert use.
For more information, see :ref:`trust_anchors_description` in the
:doc:`dnssec-guide`.

The BIND authoritative server does not verify signatures on load, so zone keys
for authoritative zones do not need to be specified in the configuration
file.

Validation Failures
^^^^^^^^^^^^^^^^^^^

When DNSSEC validation is configured, the resolver rejects any answers from
signed, secure zones which fail to validate, and returns SERVFAIL to the
client.

Responses may fail to validate for any of several reasons, including
missing, expired, or invalid signatures; a key which does not match the
DS RRset in the parent zone; or an insecure response from a zone which,
according to its parent, should have been secure.

For more information see :ref:`dnssec_troubleshooting`.

Coexistence With Unsigned (Insecure) Zones
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Zones not protected by DNSSEC are called "insecure," and these zones seamlessly
coexist with signed zones.

When the validator receives a response from an unsigned zone that has
a signed parent, it must confirm with the parent that the zone was
intentionally left unsigned. It does this by verifying, via signed
and validated :ref:`NSEC/NSEC3 records
<advanced_discussions_proof_of_nonexistence>`, that the parent zone contains no
DS records for the child.

If the validator *can* prove that the zone is insecure, then the
response is accepted. However, if it cannot, the validator must assume an
insecure response to be a forgery; it rejects the response and logs
an error.

The logged error reads "insecurity proof failed" and "got insecure
response; parent indicates it should be secure."
