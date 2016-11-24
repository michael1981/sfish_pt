# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-21.xml
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
 script_id(24887);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200703-21");
 script_cve_id("CVE-2006-5465", "CVE-2007-0906", "CVE-2007-0907", "CVE-2007-0908", "CVE-2007-0909", "CVE-2007-0910", "CVE-2007-0911", "CVE-2007-0988", "CVE-2007-1286", "CVE-2007-1375", "CVE-2007-1376", "CVE-2007-1380", "CVE-2007-1383");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-21
(PHP: Multiple vulnerabilities)


    Several vulnerabilities were found in PHP by the Hardened-PHP Project
    and other researchers. These vulnerabilities include a heap-based
    buffer overflow in htmlentities() and htmlspecialchars() if called with
    UTF-8 parameters, and an off-by-one error in str_ireplace(). Other
    vulnerabilities were also found in the PHP4 branch, including possible
    overflows, stack corruptions and a format string vulnerability in the
    *print() functions on 64 bit systems.
  
Impact

    Remote attackers might be able to exploit these issues in PHP
    applications making use of the affected functions, potentially
    resulting in the execution of arbitrary code, Denial of Service,
    execution of scripted contents in the context of the affected site,
    security bypass or information leak.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "dev-lang/php"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-5465');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0906');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0907');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0908');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0909');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0910');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0911');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0988');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1286');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1375');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1376');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1380');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1383');
script_set_attribute(attribute: 'see_also', value: 'http://www.php.net/releases/4_4_5.php');
script_set_attribute(attribute: 'see_also', value: 'http://www.php.net/releases/5_2_1.php');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-21] PHP: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/php", unaffected: make_list("ge 5.2.1-r3", "rge 5.1.6-r11", "rge 4.4.6", "rge 4.4.7", "rge 4.4.8_pre20070816"), vulnerable: make_list("lt 5.2.1-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
