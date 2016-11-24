# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200501-28.xml
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
 script_id(16419);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200501-28");
 script_cve_id("CVE-2005-0064");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200501-28 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200501-28
(Xpdf, GPdf: Stack overflow in Decrypt::makeFileKey2)


    iDEFENSE reports that the Decrypt::makeFileKey2 function in Xpdf\'s
    Decrypt.cc insufficiently checks boundaries when processing /Encrypt
    /Length tags in PDF files.
  
Impact

    An attacker could entice an user to open a specially-crafted PDF
    file which would trigger a stack overflow, potentially resulting in
    execution of arbitrary code with the rights of the user running Xpdf or
    GPdf.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.00-r8"
    All GPdf users should also upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/gpdf-2.8.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0064');
script_set_attribute(attribute: 'see_also', value: 'http://www.idefense.com/application/poi/display?id=186&type=vulnerabilities&flashstatus=true');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200501-28.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200501-28] Xpdf, GPdf: Stack overflow in Decrypt::makeFileKey2');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf, GPdf: Stack overflow in Decrypt::makeFileKey2');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/gpdf", unaffected: make_list("ge 2.8.2"), vulnerable: make_list("lt 2.8.2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.00-r8"), vulnerable: make_list("le 3.00-r7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
