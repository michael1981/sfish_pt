# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-30.xml
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
 script_id(18169);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200504-30");
 script_cve_id("CVE-2005-1392");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-30 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-30
(phpMyAdmin: Insecure SQL script installation)


    The phpMyAdmin installation process leaves the SQL install script with
    insecure permissions.
  
Impact

    A local attacker could exploit this vulnerability to obtain the initial
    phpMyAdmin password and from there obtain information about databases
    accessible by phpMyAdmin.
  
Workaround

    Change the password for the phpMyAdmin MySQL user (pma):
    mysql -u root -p
    SET PASSWORD FOR \'pma\'@\'localhost\' = PASSWORD(\'MyNewPassword\');
    Update your phpMyAdmin config.inc.php:
    $cfg[\'Servers\'][$i][\'controlpass\']   = \'MyNewPassword\';
  
');
script_set_attribute(attribute:'solution', value: '
    All phpMyAdmin users should change password for the pma user as
    described above and upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.6.2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1392');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-30.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-30] phpMyAdmin: Insecure SQL script installation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Insecure SQL script installation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.6.2-r1"), vulnerable: make_list("lt 2.6.2-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
