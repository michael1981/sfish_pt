# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-01.xml
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
 script_id(14648);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200409-01");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-01
(vpopmail: Multiple vulnerabilities)


    vpopmail is vulnerable to several unspecified SQL injection exploits.
    Furthermore when using Sybase as the backend database vpopmail is
    vulnerable to a buffer overflow and format string exploit.
  
Impact

    These vulnerabilities could allow an attacker to execute code with the
    permissions of the user running vpopmail.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of vpopmail.
  
');
script_set_attribute(attribute:'solution', value: '
    All vpopmail users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-mail/vpopmail-5.4.6"
    # emerge ">=net-mail/vpopmail-5.4.6"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/forum/forum.php?forum_id=400873');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/371913/2004-08-15/2004-08-21/0');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-01] vpopmail: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'vpopmail: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/vpopmail", unaffected: make_list("ge 5.4.6"), vulnerable: make_list("lt 5.4.6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
