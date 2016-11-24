# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200805-16.xml
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
 script_id(32353);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200805-16");
 script_cve_id("CVE-2007-4770", "CVE-2007-4771", "CVE-2007-5745", "CVE-2007-5746", "CVE-2007-5747", "CVE-2008-0320");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200805-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200805-16
(OpenOffice.org: Multiple vulnerabilities)


    iDefense Labs reported multiple vulnerabilities in OpenOffice.org:
    multiple heap-based buffer overflows when parsing the "Attribute" and
    "Font" Description records of Quattro Pro (QPRO) files
    (CVE-2007-5745),
    an integer overflow when parsing the EMR_STRETCHBLT record of an EMF
    file, resulting in a heap-based buffer overflow (CVE-2007-5746),
    an integer underflow when parsing Quattro Pro (QPRO) files, resulting
    in an excessive loop and a stack-based buffer overflow
    (CVE-2007-5747),
    and a heap-based buffer overflow when parsing the
    "DocumentSummaryInformation" stream in an OLE file (CVE-2008-0320).
    Furthermore, Will Drewry (Google Security) reported vulnerabilities in
    the memory management of the International Components for Unicode
    (CVE-2007-4770, CVE-2007-4771), which was resolved with GLSA 200803-20.
    However, the binary version of OpenOffice.org uses an internal copy of
    said library.
  
Impact

    A remote attacker could entice a user to open a specially crafted
    document, possibly resulting in the remote execution of arbitrary code
    with the privileges of the user running OpenOffice.org.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenOffice.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-2.4.0"
    All OpenOffice.org binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-bin-2.4.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4770');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4771');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5745');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5746');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5747');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0320');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-20.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200805-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200805-16] OpenOffice.org: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 2.4.0"), vulnerable: make_list("lt 2.4.0")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 2.4.0"), vulnerable: make_list("lt 2.4.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
