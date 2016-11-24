# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-22.xml
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
 script_id(28261);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200711-22");
 script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-22
(Poppler, KDE: User-assisted execution of arbitrary code)


    Alin Rad Pop (Secunia Research) discovered several vulnerabilities in
    the "Stream.cc" file of Xpdf: An integer overflow in the
    DCTStream::reset() method and a boundary error in the
    CCITTFaxStream::lookChar() method, both leading to heap-based buffer
    overflows (CVE-2007-5392, CVE-2007-5393). He also discovered a boundary
    checking error in the DCTStream::readProgressiveDataUnit() method
    causing memory corruption (CVE-2007-4352). Note: Gentoo\'s version of
    Xpdf is patched to use the Poppler library, so the update to Poppler
    will also fix Xpdf.
  
Impact

    By enticing a user to view or process a specially crafted PDF file with
    KWord or KPDF or a Poppler-based program such as Gentoo\'s viewers Xpdf,
    ePDFView, and Evince or the CUPS printing system, a remote attacker
    could cause an overflow, potentially resulting in the execution of
    arbitrary code with the privileges of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Poppler users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/poppler-0.6.1-r1"
    All KPDF users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kpdf-3.5.7-r3"
    All KDE Graphics Libraries users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdegraphics-3.5.7-r3"
    All KWord users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/kword-1.6.3-r2"
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/koffice-1.6.3-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4352');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5392');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5393');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-22] Poppler, KDE: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Poppler, KDE: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("rge 3.5.7-r3", "ge 3.5.8-r1"), vulnerable: make_list("lt 3.5.8-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-text/poppler", unaffected: make_list("ge 0.6.1-r1"), vulnerable: make_list("lt 0.6.1-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/kword", unaffected: make_list("ge 1.6.3-r2"), vulnerable: make_list("lt 1.6.3-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/koffice", unaffected: make_list("ge 1.6.3-r2"), vulnerable: make_list("lt 1.6.3-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "kde-base/kpdf", unaffected: make_list("rge 3.5.7-r3", "ge 3.5.8-r1"), vulnerable: make_list("lt 3.5.8-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
