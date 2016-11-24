# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200412-02.xml
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
 script_id(15906);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200412-02");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200412-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200412-02
(PDFlib: Multiple overflows in the included TIFF library)


    The TIFF library is subject to several known vulnerabilities (see
    GLSA 200410-11). Most of these overflows also apply to PDFlib.
  
Impact

    A remote attacker could entice a user or web application to
    process a carefully crafted PDF file or TIFF image using a
    PDFlib-powered program. This can potentially lead to the execution of
    arbitrary code with the rights of the program processing the file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PDFlib users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/pdflib-5.0.4_p1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.pdflib.com/products/pdflib/info/PDFlib-5.0.4p1-changes.txt');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0803');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0804');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0886');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-11.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200412-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200412-02] PDFlib: Multiple overflows in the included TIFF library');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PDFlib: Multiple overflows in the included TIFF library');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/pdflib", unaffected: make_list("ge 5.0.4_p1"), vulnerable: make_list("lt 5.0.4_p1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
