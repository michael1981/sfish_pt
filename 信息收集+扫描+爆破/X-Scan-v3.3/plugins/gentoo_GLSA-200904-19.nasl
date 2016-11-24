# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200904-19.xml
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
 script_id(36198);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200904-19");
 script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200904-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200904-19
(LittleCMS: Multiple vulnerabilities)


    RedHat reported a null-pointer dereference flaw while processing
    monochrome ICC profiles (CVE-2009-0793).
    Chris Evans of Google discovered the following vulnerabilities:
    LittleCMS contains severe memory leaks (CVE-2009-0581).
    LittleCMS is prone to multiple integer overflows, leading to a
    heap-based buffer overflow (CVE-2009-0723).
    The
    ReadSetOfCurves() function is vulnerable to stack-based buffer
    overflows when called from code paths without a bounds check on channel
    counts (CVE-2009-0733).
  
Impact

    A remote attacker could entice a user or automated system to open a
    specially crafted file containing a malicious ICC profile, possibly
    resulting in the execution of arbitrary code with the privileges of the
    user running the application or memory exhaustion, leading to a Denial
    of Service condition.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All LittleCMS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/lcms-1.18-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0581');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0723');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0733');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0793');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200904-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200904-19] LittleCMS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LittleCMS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/lcms", unaffected: make_list("ge 1.18-r1"), vulnerable: make_list("lt 1.18-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
