# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200909-16.xml
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
 script_id(40963);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200909-16");
 script_cve_id("CVE-2009-2559", "CVE-2009-2560", "CVE-2009-2561", "CVE-2009-2562", "CVE-2009-2563");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200909-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200909-16
(Wireshark: Denial of Service)


    Multiple vulnerabilities were discovered in Wireshark:
    A
    buffer overflow in the IPMI dissector related to an array index error
    (CVE-2009-2559).
    Multiple unspecified vulnerabilities in the
    Bluetooth L2CAP, RADIUS, and MIOP dissectors (CVE-2009-2560).
    An unspecified vulnerability in the sFlow dissector
    (CVE-2009-2561).
    An unspecified vulnerability in the AFS
    dissector (CVE-2009-2562).
    An unspecified vulnerability in the
    Infiniband dissector when running on unspecified platforms
    (CVE-2009-2563).
  
Impact

    A remote attacker could exploit these vulnerabilities by sending
    specially crafted packets on a network being monitored by Wireshark or
    by enticing a user to read a malformed packet trace file to cause a
    Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =net-analyzer/wireshark-1.2.1
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2559');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2560');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2561');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2562');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2563');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200909-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200909-16] Wireshark: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wireshark: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/wireshark", unaffected: make_list("ge 1.2.1"), vulnerable: make_list("lt 1.2.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
