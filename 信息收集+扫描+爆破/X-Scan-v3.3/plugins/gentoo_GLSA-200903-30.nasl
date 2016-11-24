# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-30.xml
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
 script_id(35943);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-30");
 script_cve_id("CVE-2008-5178", "CVE-2008-5679", "CVE-2008-5680", "CVE-2008-5681", "CVE-2008-5682", "CVE-2008-5683", "CVE-2009-0914");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-30 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-30
(Opera: Multiple vulnerabilities)


    Multiple vulnerabilities were discovered in Opera:
    Vitaly McLain reported a heap-based buffer overflow when processing
    host names in file:// URLs (CVE-2008-5178).
    Alexios Fakos reported a vulnerability in the HTML parsing engine
    when processing web pages that trigger an invalid pointer calculation
    and heap corruption (CVE-2008-5679).
    Red XIII reported that certain text-area contents can be
    manipulated to cause a buffer overlow (CVE-2008-5680).
    David Bloom discovered that unspecified "scripted URLs" are not
    blocked during the feed preview (CVE-2008-5681).
    Robert Swiecki of the Google Security Team reported a Cross-site
    scripting vulnerability (CVE-2008-5682).
    An unspecified vulnerability reveals random data
    (CVE-2008-5683).
    Tavis Ormandy of the Google Security Team reported a vulnerability
    when processing JPEG images that may corrupt memory
    (CVE-2009-0914).
  
Impact

    A remote attacker could entice a user to open a specially crafted JPEG
    image to cause a Denial of Service or execute arbitrary code, to
    process an overly long file:// URL or to open a specially crafted web
    page to execute arbitrary code. He could also read existing
    subscriptions and force subscriptions to arbitrary feed URLs, as well
    as inject arbitrary web script or HTML via built-in XSLT templates.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Opera users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-client/opera-9.64"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5178');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5679');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5680');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5681');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5682');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5683');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0914');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-30.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-30] Opera: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Opera: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-client/opera", unaffected: make_list("ge 9.64"), vulnerable: make_list("lt 9.64")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
