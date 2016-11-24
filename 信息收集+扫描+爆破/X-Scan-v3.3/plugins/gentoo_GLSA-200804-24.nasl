# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-24.xml
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
 script_id(32017);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200804-24");
 script_cve_id("CVE-2007-6714");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-24
(DBmail: Data disclosure)


    A vulnerability in DBMail\'s authldap module when used in conjunction
    with an Active Directory server has been reported by vugluskr. When
    passing a zero length password to the module, it tries to bind
    anonymously to the LDAP server. If the LDAP server allows anonymous
    binds, this bind succeeds and results in a successful authentication to
    DBMail.
  
Impact

    By passing an empty password string to the server, an attacker could be
    able to log in to any account.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All DBMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-mail/dbmail-2.2.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6714');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-24] DBmail: Data disclosure');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'DBmail: Data disclosure');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-mail/dbmail", unaffected: make_list("ge 2.2.9"), vulnerable: make_list("lt 2.2.9")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
