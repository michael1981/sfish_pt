# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-20.xml
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
 script_id(15539);
 script_version("$Revision: 1.9 $");
 script_xref(name: "GLSA", value: "200410-20");
 script_cve_id("CVE-2004-0888", "CVE-2004-0889");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-20
(Xpdf, CUPS: Multiple integer overflows)


    Chris Evans discovered multiple integer overflow issues in Xpdf.
  
Impact

    An attacker could entice an user to open a specially-crafted PDF file,
    potentially resulting in execution of arbitrary code with the rights of the
    user running Xpdf. By enticing an user to directly print the PDF file to a
    CUPS printer, an attacker could also crash the CUPS spooler or execute
    arbitrary code with the rights of the CUPS spooler, which is usually the
    "lp" user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.00-r5"
    All CUPS users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.1.20-r5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0888');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0889');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-20] Xpdf, CUPS: Multiple integer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf, CUPS: Multiple integer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.1.20-r5"), vulnerable: make_list("le 1.1.20-r4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.00-r5"), vulnerable: make_list("le 3.00-r4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
