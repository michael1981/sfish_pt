# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-02.xml
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
 script_id(20412);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200601-02");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200601-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200601-02
(KPdf, KWord: Multiple overflows in included Xpdf code)


    KPdf and KWord both include Xpdf code to handle PDF files. This Xpdf
    code is vulnerable to several heap overflows (GLSA 200512-08) as well
    as several buffer and integer overflows discovered by Chris Evans
    (CESA-2005-003).
  
Impact

    An attacker could entice a user to open a specially crafted PDF file
    with Kpdf or KWord, potentially resulting in the execution of arbitrary
    code with the rights of the user running the affected application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All kdegraphics users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kdegraphics-3.4.3-r3"
    All Kpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=kde-base/kpdf-3.4.3-r3"
    All KOffice users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/koffice-1.4.2-r6"
    All KWord users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/kword-1.4.2-r6"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-3191');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-3192');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-3193');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3624');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3625');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3626');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3627');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3628');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-08.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.kde.org/info/security/advisory-20051207-2.txt');
script_set_attribute(attribute: 'see_also', value: 'http://scary.beasts.org/security/CESA-2005-003.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200601-02] KPdf, KWord: Multiple overflows in included Xpdf code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'KPdf, KWord: Multiple overflows in included Xpdf code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "kde-base/kdegraphics", unaffected: make_list("ge 3.4.3-r3"), vulnerable: make_list("lt 3.4.3-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/kword", unaffected: make_list("ge 1.4.2-r6"), vulnerable: make_list("lt 1.4.2-r6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-office/koffice", unaffected: make_list("ge 1.4.2-r6"), vulnerable: make_list("lt 1.4.2-r6")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "kde-base/kpdf", unaffected: make_list("ge 3.4.3-r3"), vulnerable: make_list("lt 3.4.3-r3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
