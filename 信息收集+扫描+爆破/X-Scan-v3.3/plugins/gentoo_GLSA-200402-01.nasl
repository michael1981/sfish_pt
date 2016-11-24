# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200402-01.xml
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
 script_id(14445);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200402-01");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200402-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200402-01
(PHP setting leaks from .htaccess files on virtual hosts)


    If the server configuration "php.ini" file has
    "register_globals = on" and a request is made to one virtual host
    (which has "php_admin_flag register_globals off") and the next
    request is sent to the another virtual host (which does not have the
    setting) through the same apache child, the setting will persist.
  
Impact

    Depending on the server and site, an attacker may be able to exploit
    global variables to gain access to reserved areas, such as MySQL passwords,
    or this vulnerability may simply cause a lack of functionality. As a
    result, users are urged to upgrade their PHP installations.
    Gentoo ships PHP with "register_globals" set to "off"
    by default.
    This issue affects both servers running Apache 1.x and servers running
    Apache 2.x.
  
Workaround

    No immediate workaround is available; a software upgrade is required.
  
');
script_set_attribute(attribute:'solution', value: '
    All users are recommended to upgrade their PHP installation to 4.3.4-r4:
    # emerge sync
    # emerge -pv ">=dev-php/mod_php-4.3.4-r4"
    # emerge ">=dev-php/mod_php-4.3.4-r4"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.php.net/bug.php?id=25753');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200402-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200402-01] PHP setting leaks from .htaccess files on virtual hosts');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP setting leaks from .htaccess files on virtual hosts');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("ge 4.3.4-r4"), vulnerable: make_list("lt 4.3.4-r4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
