# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-09.xml
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
 script_id(22107);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200607-09");
 script_cve_id("CVE-2006-3627", "CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200607-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200607-09
(Wireshark: Multiple vulnerabilities)


    Wireshark dissectors have been found vulnerable to a large number of
    exploits, including off-by-one errors, buffer overflows, format string
    overflows and an infinite loop.
  
Impact

    Running an affected version of Wireshark or Ethereal could allow for a
    remote attacker to execute arbitrary code on the user\'s computer by
    sending specially crafted packets.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/wireshark-0.99.2"
    All Ethereal users should migrate to Wireshark:
    # emerge --sync
    # emerge --ask --unmerge net-analyzer/ethereal
    # emerge --ask --oneshot --verbose ">=net-analyzer/wireshark-0.99.2"
    To keep the [saved] configuration from Ethereal and reuse it with
    Wireshark:
    # mv ~/.ethereal ~/.wireshark
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.wireshark.org/security/wnpa-sec-2006-01.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3627');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3628');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3629');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3630');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3631');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3632');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200607-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200607-09] Wireshark: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wireshark: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/ethereal", unaffected: make_list(), vulnerable: make_list("le 0.99.0-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-analyzer/wireshark", unaffected: make_list("ge 0.99.2"), vulnerable: make_list("lt 0.99.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
