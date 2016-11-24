# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml
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
 script_id(28319);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200711-30");
 script_cve_id("CVE-2006-7227", "CVE-2006-7228", "CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660", "CVE-2007-1661", "CVE-2007-1662", "CVE-2007-4766", "CVE-2007-4767", "CVE-2007-4768");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-30 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-30
(PCRE: Multiple vulnerabilities)


    Tavis Ormandy (Google Security) discovered multiple vulnerabilities in
    PCRE. He reported an error when processing "\\Q\\E" sequences with
    unmatched "\\E" codes that can lead to the compiled bytecode being
    corrupted (CVE-2007-1659). PCRE does not properly calculate sizes for
    unspecified "multiple forms of character class", which triggers a
    buffer overflow (CVE-2007-1660). Further improper calculations of
    memory boundaries were reported when matching certain input bytes
    against regex patterns in non UTF-8 mode (CVE-2007-1661) and when
    searching for unmatched brackets or parentheses (CVE-2007-1662).
    Multiple integer overflows when processing escape sequences may lead to
    invalid memory read operations or potentially cause heap-based buffer
    overflows (CVE-2007-4766). PCRE does not properly handle "\\P" and
    "\\P{x}" sequences which can lead to heap-based buffer overflows or
    trigger the execution of infinite loops (CVE-2007-4767), PCRE is also
    prone to an error when optimizing character classes containing a
    singleton UTF-8 sequence which might lead to a heap-based buffer
    overflow (CVE-2007-4768).
    Chris Evans also reported multiple integer overflow vulnerabilities in
    PCRE when processing a large number of named subpatterns ("name_count")
    or long subpattern names ("max_name_size") (CVE-2006-7227), and via
    large "min", "max", or "duplength" values (CVE-2006-7228) both possibly
    leading to buffer overflows. Another vulnerability was reported when
    compiling patterns where the "-x" or "-i" UTF-8 options change within
    the pattern, which might lead to improper memory calculations
    (CVE-2006-7230).
  
Impact

    An attacker could exploit these vulnerabilities by sending specially
    crafted regular expressions to applications making use of the PCRE
    library, which could possibly lead to the execution of arbitrary code,
    a Denial of Service or the disclosure of sensitive information.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PCRE users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/libpcre-7.3-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-7227');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-7228');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-7230');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1659');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1660');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1661');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1662');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4766');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4767');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4768');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-30.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-30] PCRE: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PCRE: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/libpcre", unaffected: make_list("ge 7.3-r1"), vulnerable: make_list("lt 7.3-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
