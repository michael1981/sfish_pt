# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200508-12.xml
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
 script_id(19485);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200508-12");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200508-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200508-12
(Evolution: Format string vulnerabilities)


    Ulf Harnhammar discovered that Evolution is vulnerable to format
    string bugs when viewing attached vCards and when displaying contact
    information from remote LDAP servers or task list data from remote
    servers (CAN-2005-2549). He also discovered that Evolution fails to
    handle special calendar entries if the user switches to the Calendars
    tab (CAN-2005-2550).
  
Impact

    An attacker could attach specially crafted vCards to emails or
    setup malicious LDAP servers or calendar entries which would trigger
    the format string vulnerabilities when viewed or accessed from
    Evolution. This could potentially result in the execution of arbitrary
    code with the rights of the user running Evolution.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Evolution users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/evolution-2.2.3-r3"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2549');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2550');
script_set_attribute(attribute: 'see_also', value: 'http://www.sitic.se/eng/advisories_and_recommendations/sa05-001.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200508-12] Evolution: Format string vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Evolution: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/evolution", unaffected: make_list("ge 2.2.3-r3"), vulnerable: make_list("lt 2.2.3-r3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
