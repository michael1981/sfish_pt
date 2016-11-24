# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200906-05.xml
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
 script_id(39580);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200906-05");
 script_cve_id("CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4682", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685", "CVE-2008-5285", "CVE-2008-6472", "CVE-2009-0599", "CVE-2009-0600", "CVE-2009-0601", "CVE-2009-1210", "CVE-2009-1266", "CVE-2009-1268", "CVE-2009-1269", "CVE-2009-1829");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200906-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200906-05
(Wireshark: Multiple vulnerabilities)


    Multiple vulnerabilities have been discovered in Wireshark:
    David Maciejak discovered a vulnerability in packet-usb.c in the USB
    dissector via a malformed USB Request Block (URB) (CVE-2008-4680).
    Florent Drouin and David Maciejak reported an unspecified vulnerability
    in the Bluetooth RFCOMM dissector (CVE-2008-4681).
    A malformed Tamos CommView capture file (aka .ncf file) with an
    "unknown/unexpected packet type" triggers a failed assertion in wtap.c
    (CVE-2008-4682).
    An unchecked packet length parameter in the dissect_btacl() function in
    packet-bthci_acl.c in the Bluetooth ACL dissector causes an erroneous
    tvb_memcpy() call (CVE-2008-4683).
    A vulnerability where packet-frame does not properly handle exceptions
    thrown by post dissectors caused by a certain series of packets
    (CVE-2008-4684).
    Mike Davies reported a use-after-free vulnerability in the
    dissect_q931_cause_ie() function in packet-q931.c in the Q.931
    dissector via certain packets that trigger an exception
    (CVE-2008-4685).
    The Security Vulnerability Research Team of Bkis reported that the SMTP
    dissector could consume excessive amounts of CPU and memory
    (CVE-2008-5285).
    The vendor reported that the WLCCP dissector could go into an infinite
    loop (CVE-2008-6472).
    babi discovered a buffer overflow in wiretap/netscreen.c via a
    malformed NetScreen snoop file (CVE-2009-0599).
    A specially crafted Tektronix K12 text capture file can cause an
    application crash (CVE-2009-0600).
    A format string vulnerability via format string specifiers in the HOME
    environment variable (CVE-2009-0601).
    THCX Labs reported a format string vulnerability in the
    PROFINET/DCP (PN-DCP) dissector via a PN-DCP packet with format string
    specifiers in the station name (CVE-2009-1210).
    An unspecified vulnerability with unknown impact and attack vectors
    (CVE-2009-1266).
    Marty Adkins and Chris Maynard discovered a parsing error in the
    dissector for the Check Point High-Availability Protocol (CPHAP)
    (CVE-2009-1268).
    Magnus Homann discovered a parsing error when loading a Tektronix .rf5
    file (CVE-2009-1269).
    The vendor reported that the PCNFSD dissector could crash
    (CVE-2009-1829).
  
Impact

    A remote attacker could exploit these vulnerabilities by sending
    specially crafted packets on a network being monitored by Wireshark or
    by enticing a user to read a malformed packet trace file which can
    trigger a Denial of Service (application crash or excessive CPU and
    memory usage) and possibly allow for the execution of arbitrary code
    with the privileges of the user running Wireshark.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/wireshark-1.0.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4680');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4681');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4682');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4683');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4684');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4685');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5285');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6472');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0599');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0600');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0601');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1210');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1266');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1268');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1269');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1829');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200906-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200906-05] Wireshark: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wireshark: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/wireshark", unaffected: make_list("ge 1.0.8"), vulnerable: make_list("lt 1.0.8")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
