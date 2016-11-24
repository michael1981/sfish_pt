# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200404-16.xml
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
 script_id(14481);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200404-16");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200404-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200404-16
(Multiple new security vulnerabilities in monit)


    Monit has several vulnerabilities in its HTTP interface : a buffer overflow
    vulnerability in the authentication handling code and a off-by-one error in
    the POST method handling code.
  
Impact

    An attacker may exploit the off-by-one error to crash the Monit daemon and
    create a denial of service condition, or cause a buffer overflow that would
    allow arbitrary code to be executed with root privileges.
  
Workaround

    A workaround is not currently known for this issue. All users are advised
    to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    Monit users should upgrade to version 4.2.1 or later:
    # emerge sync
    # emerge -pv ">=app-admin/monit-4.2.1"
    # emerge ">=app-admin/monit-4.2.1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://www.tildeslash.com/monit/secadv_20040305.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200404-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200404-16] Multiple new security vulnerabilities in monit');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple new security vulnerabilities in monit');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/monit", unaffected: make_list("ge 4.2.1"), vulnerable: make_list("le 4.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
