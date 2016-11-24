# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-06.xml
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
 script_id(35023);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200812-06");
 script_cve_id("CVE-2008-3281", "CVE-2008-3529", "CVE-2008-4409", "CVE-2008-4225", "CVE-2008-4226");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-06 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-06
(libxml2: Multiple vulnerabilities)


    Multiple vulnerabilities were reported in libxml2:
    Andreas Solberg reported that libxml2 does not properly detect
    recursion during entity expansion in an attribute value
    (CVE-2008-3281).
    A heap-based buffer overflow has been reported in the
    xmlParseAttValueComplex() function in parser.c (CVE-2008-3529).
    Christian Weiske reported that predefined entity definitions in
    entities are not properly handled (CVE-2008-4409).
    Drew Yao of Apple Product Security reported an integer overflow in the
    xmlBufferResize() function that can lead to an infinite loop
    (CVE-2008-4225).
    Drew Yao of Apple Product Security reported an integer overflow in the
    xmlSAX2Characters() function leading to a memory corruption
    (CVE-2008-4226).
  
Impact

    A remote attacker could entice a user or automated system to open a
    specially crafted XML document with an application using libxml2,
    possibly resulting in the exeution of arbitrary code or a high CPU and
    memory consumption.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All libxml2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-libs/libxml2-2.7.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3281');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3529');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4409');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4225');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4226');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-06.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-06] libxml2: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'libxml2: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-libs/libxml2", unaffected: make_list("ge 2.7.2-r1"), vulnerable: make_list("lt 2.7.2-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
