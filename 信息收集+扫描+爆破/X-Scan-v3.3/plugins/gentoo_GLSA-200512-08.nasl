# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-08.xml
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
 script_id(20328);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-08");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-08
(Xpdf, GPdf, CUPS, Poppler: Multiple vulnerabilities)


    infamous41md discovered that several Xpdf functions lack sufficient
    boundary checking, resulting in multiple exploitable buffer overflows.
  
Impact

    An attacker could entice a user to open a specially-crafted PDF file
    which would trigger an overflow, potentially resulting in execution of
    arbitrary code with the rights of the user running Xpdf, CUPS, GPdf or
    Poppler.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Xpdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/xpdf-3.01-r2"
    All GPdf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-text/gpdf-2.10.0-r2"
    All Poppler users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-text/poppler
    All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.1.23-r3"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3191');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3192');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3193');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-08] Xpdf, GPdf, CUPS, Poppler: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Xpdf, GPdf, CUPS, Poppler: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/gpdf", unaffected: make_list("ge 2.10.0-r2"), vulnerable: make_list("lt 2.10.0-r2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/poppler", unaffected: make_list("ge 0.4.2-r1", "rge 0.3.0-r1"), vulnerable: make_list("lt 0.4.2-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "net-print/cups", unaffected: make_list("ge 1.1.23-r3"), vulnerable: make_list("lt 1.1.23-r3")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-text/xpdf", unaffected: make_list("ge 3.01-r2"), vulnerable: make_list("lt 3.01-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
