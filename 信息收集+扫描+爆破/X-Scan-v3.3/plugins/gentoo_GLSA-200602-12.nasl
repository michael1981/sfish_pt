# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-12.xml
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
 script_id(20962);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200602-12");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200602-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200602-12
(GPdf: heap overflows in included Xpdf code)


    Dirk Mueller found a heap overflow vulnerability in the XPdf
    codebase when handling splash images that exceed size of the associated
    bitmap.
  
Impact

    An attacker could entice a user to open a specially crafted PDF
    file with GPdf, potentially resulting in the execution of arbitrary
    code with the rights of the user running the affected application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GPdf users should upgrade to the latest version.
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/gpdf-2.10.0-r4"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0301');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200602-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200602-12] GPdf: heap overflows in included Xpdf code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GPdf: heap overflows in included Xpdf code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/gpdf", unaffected: make_list("ge 2.10.0-r4"), vulnerable: make_list("lt 2.10.0-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
