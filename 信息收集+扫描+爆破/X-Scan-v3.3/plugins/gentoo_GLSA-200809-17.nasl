# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-17.xml
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
 script_id(34298);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200809-17");
 script_cve_id("CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933", "CVE-2008-3934");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-17 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-17
(Wireshark: Multiple Denials of Service)


    The following vulnerabilities were reported:
    Multiple buffer overflows in the NCP dissector (CVE-2008-3146).
    Infinite loop in the NCP dissector (CVE-2008-3932).
    Invalid read in the tvb_uncompress() function when processing zlib
    compressed data (CVE-2008-3933).
    Unspecified error when processing Textronix .rf5 files
    (CVE-2008-3934).
  
Impact

    A remote attacker could exploit these vulnerabilities by sending
    specially crafted packets on a network being monitored by Wireshark or
    by enticing a user to read a malformed packet trace file, causing a
    Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/wireshark-1.0.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3146');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3932');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3933');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3934');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-17.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-17] Wireshark: Multiple Denials of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wireshark: Multiple Denials of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/wireshark", unaffected: make_list("ge 1.0.3"), vulnerable: make_list("lt 1.0.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
