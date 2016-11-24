# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200710-20.xml
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
 script_id(27518);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200710-20");
 script_cve_id("CVE-2007-3387");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200710-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200710-20
(PDFKit, ImageKits: Buffer overflow)


    Maurycy Prodeus discovered an integer overflow vulnerability possibly
    leading to a stack-based buffer overflow in the XPDF code which PDFKit
    is based on. ImageKits also contains a copy of PDFKit.
  
Impact

    By enticing a user to view a specially crafted PDF file with a viewer
    based on ImageKits or PDFKit such as Gentoo\'s ViewPDF, a remote
    attacker could cause an overflow, potentially resulting in the
    execution of arbitrary code with the privileges of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    PDFKit and ImageKits are not maintained upstream, so the packages were
    masked in Portage. We recommend that users unmerge PDFKit and
    ImageKits:
    # emerge --unmerge gnustep-libs/pdfkit
    # emerge --unmerge gnustep-libs/imagekits
    As an alternative, users should upgrade their systems to use PopplerKit
    instead of PDFKit and Vindaloo instead of ViewPDF.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3387');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-12.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200710-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200710-20] PDFKit, ImageKits: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PDFKit, ImageKits: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "gnustep-libs/pdfkit", unaffected: make_list(), vulnerable: make_list("le 0.9_pre062906")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "gnustep-libs/imagekits", unaffected: make_list(), vulnerable: make_list("le 0.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
