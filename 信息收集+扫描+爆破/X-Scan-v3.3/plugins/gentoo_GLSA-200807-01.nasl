# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200807-01.xml
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
 script_id(33421);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200807-01");
 script_cve_id("CVE-2008-1679", "CVE-2008-1721", "CVE-2008-1887");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200807-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200807-01
(Python: Multiple integer overflows)


    Multiple vulnerabilities were discovered in Python:
    David
    Remahl reported multiple integer overflows in the file imageop.c,
    leading to a heap-based buffer overflow (CVE-2008-1679). This issue is
    due to an incomplete fix for CVE-2007-4965.
    Justin Ferguson
    discovered that an integer signedness error in the zlib extension
    module might trigger insufficient memory allocation and a buffer
    overflow via a negative signed integer (CVE-2008-1721).
    Justin
    Ferguson discovered that insufficient input validation in the
    PyString_FromStringAndSize() function might lead to a buffer overflow
    (CVE-2008-1887).
  
Impact

    A remote attacker could exploit these vulnerabilities to cause a Denial
    of Service or possibly the remote execution of arbitrary code with the
    privileges of the user running Python.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    The imageop module is no longer built in the unaffected versions.
    All Python 2.3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.3.6-r6"
    All Python 2.4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/python-2.4.4-r13"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1679');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1721');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1887');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200807-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200807-01] Python: Multiple integer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Python: Multiple integer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/python", unaffected: make_list("rge 2.3.6-r6", "ge 2.4.4-r13"), vulnerable: make_list("lt 2.4.4-r13")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
