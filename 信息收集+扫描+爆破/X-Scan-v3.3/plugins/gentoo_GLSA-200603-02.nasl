# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-02.xml
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
 script_id(21000);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-02");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-02
(teTeX, pTeX, CSTeX: Multiple overflows in included XPdf code)


    CSTeX, teTex, and pTeX include XPdf code to handle PDF files. This
    XPdf code is vulnerable to several heap overflows (GLSA 200512-08) as
    well as several buffer and integer overflows discovered by Chris Evans
    (CESA-2005-003).
  
Impact

    An attacker could entice a user to open a specially crafted PDF
    file with teTeX, pTeX or CSTeX, potentially resulting in the execution
    of arbitrary code with the rights of the user running the affected
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All teTex users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/tetex-2.0.2-r8"
    All CSTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/cstetex-2.0.2-r2"
    All pTeX users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/ptex-3.1.5-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-3193');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-08.xml');
script_set_attribute(attribute: 'see_also', value: 'http://scary.beasts.org/security/CESA-2005-003.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-02] teTeX, pTeX, CSTeX: Multiple overflows in included XPdf code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'teTeX, pTeX, CSTeX: Multiple overflows in included XPdf code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/tetex", unaffected: make_list("ge 2.0.2-r8"), vulnerable: make_list("lt 2.0.2-r8")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/cstetex", unaffected: make_list("ge 2.0.2-r2"), vulnerable: make_list("lt 2.0.2-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/ptex", unaffected: make_list("ge 3.1.5-r1"), vulnerable: make_list("lt 3.1.5-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
