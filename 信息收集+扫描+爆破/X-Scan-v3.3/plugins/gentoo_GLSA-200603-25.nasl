# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-25.xml
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
 script_id(21160);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-25");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-25
(OpenOffice.org: Heap overflow in included libcurl)


    OpenOffice.org includes libcurl code. This libcurl code is
    vulnerable to a heap overflow when it tries to parse a URL that exceeds
    a 256-byte limit (GLSA 200512-09).
  
Impact

    An attacker could entice a user to call a specially crafted URL
    with OpenOffice.org, potentially resulting in the execution of
    arbitrary code with the rights of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All OpenOffice.org binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-bin-2.0.2"
    All OpenOffice.org users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-office/openoffice-2.0.1-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4077');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory_242005.109.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-09.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-25] OpenOffice.org: Heap overflow in included libcurl');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'OpenOffice.org: Heap overflow in included libcurl');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-office/openoffice-bin", unaffected: make_list("ge 2.0.2"), vulnerable: make_list("lt 2.0.2")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "app-office/openoffice", unaffected: make_list("ge 2.0.1-r1"), vulnerable: make_list("lt 2.0.1-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
