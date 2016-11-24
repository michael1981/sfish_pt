# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200908-04.xml
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
 script_id(40520);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200908-04");
 script_cve_id("CVE-2009-1862", "CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866", "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200908-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200908-04
(Adobe products: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in Adobe Flash Player:
    lakehu of Tencent Security Center reported an unspecified
    memory corruption vulnerability (CVE-2009-1862).
    Mike Wroe
    reported an unspecified vulnerability, related to "privilege
    escalation" (CVE-2009-1863).
    An anonymous researcher through
    iDefense reported an unspecified heap-based buffer overflow
    (CVE-2009-1864).
    Chen Chen of Venustech reported an
    unspecified "null pointer vulnerability" (CVE-2009-1865).
    Chen
    Chen of Venustech reported an unspecified stack-based buffer overflow
    (CVE-2009-1866).
    Joran Benker reported that Adobe Flash Player
    facilitates "clickjacking" attacks (CVE-2009-1867).
    Jun Mao of
    iDefense reported a heap-based buffer overflow, related to URL parsing
    (CVE-2009-1868).
    Roee Hay of IBM Rational Application Security
    reported an unspecified integer overflow (CVE-2009-1869).
    Gareth Heyes and Microsoft Vulnerability Research reported that the
    sandbox in Adobe Flash Player allows for information disclosure, when
    "SWFs are saved to the hard drive" (CVE-2009-1870).
  
Impact

    A remote attacker could entice a user to open a specially crafted PDF
    file or web site containing Adobe Flash (SWF) contents, possibly
    resulting in the execution of arbitrary code with the privileges of the
    user running the application, or a Denial of Service (application
    crash). Furthermore, a remote attacker could trick a user into clicking
    a button on a dialog by supplying a specially crafted SWF file and
    disclose sensitive information by exploiting a sandbox issue.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Adobe Flash Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-plugins/adobe-flash-10.0.32.18"
    All Adobe Reader users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/acroread-9.1.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1862');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1863');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1864');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1865');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1866');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1867');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1868');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1869');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1870');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200908-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200908-04] Adobe products: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Adobe products: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-plugins/adobe-flash", unaffected: make_list("ge 10.0.32.18"), vulnerable: make_list("lt 10.0.32.18")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-text/acroread", unaffected: make_list("ge 9.1.3"), vulnerable: make_list("lt 9.1.3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
