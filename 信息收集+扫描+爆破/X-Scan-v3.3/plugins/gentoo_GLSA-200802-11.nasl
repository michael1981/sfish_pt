# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-11.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(31294);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200802-11");
 script_cve_id("CVE-2007-3762", "CVE-2007-3763", "CVE-2007-3764", "CVE-2007-4103");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-11
(Asterisk: Multiple vulnerabilities)


    Multiple vulnerabilities have been found in Asterisk:
    Russel Bryant reported a stack buffer overflow in the IAX2 channel
    driver (chan_iax2) when bridging calls between chan_iax2 and any
    channel driver that uses RTP for media (CVE-2007-3762).
    Chris
    Clark and Zane Lackey (iSEC Partners) reported a NULL pointer
    dereference in the IAX2 channel driver (chan_iax2)
    (CVE-2007-3763).
    Will Drewry (Google Security) reported a
    vulnerability in the Skinny channel driver (chan_skinny), resulting in
    an overly large memcpy (CVE-2007-3764).
    Will Drewry (Google
    Security) reported a vulnerability in the IAX2 channel driver
    (chan_iax2), that does not correctly handle unauthenticated
    transactions using a 3-way handshake (CVE-2007-4103).
  
Impact

    By sending a long voice or video RTP frame, a remote attacker could
    possibly execute arbitrary code on the target machine. Sending
    specially crafted LAGRQ or LAGRP frames containing information elements
    of IAX frames, or a certain data length value in a crafted packet, or
    performing a flood of calls not completing a 3-way handshake, could
    result in a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Asterisk users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-misc/asterisk-1.2.17-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3762');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3763');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3764');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4103');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-11] Asterisk: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Asterisk: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/asterisk", unaffected: make_list("rge 1.2.17-r1", "ge 1.2.21.1-r1"), vulnerable: make_list("lt 1.2.21.1-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
