# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200812-20.xml
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
 script_id(35257);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200812-20");
 script_cve_id("CVE-2006-1495", "CVE-2008-4303", "CVE-2008-4304", "CVE-2008-4305");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200812-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200812-20
(phpCollab: Multiple vulnerabilities)


    Multiple vulnerabilities have been found in phpCollab:
    rgod reported that data sent to general/sendpassword.php via the
    loginForm parameter is not properly sanitized before being used in an
    SQL statement (CVE-2006-1495).
    Christian Hoffmann of Gentoo
    Security discovered multiple vulnerabilites where input is
    insufficiently sanitized before being used in an SQL statement, for
    instance in general/login.php via the loginForm parameter.
    (CVE-2008-4303).
    Christian Hoffmann also found out that the
    variable $SSL_CLIENT_CERT in general/login.php is not properly
    sanitized before being used in a shell command. (CVE-2008-4304).
    User-supplied data to installation/setup.php is not checked before
    being written to include/settings.php which is executed later. This
    issue was reported by Christian Hoffmann as well (CVE-2008-4305).
  
Impact

    These vulnerabilities enable remote attackers to execute arbitrary SQL
    statements and PHP code. NOTE: Some of the SQL injection
    vulnerabilities require the php.ini option "magic_quotes_gpc" to be
    disabled. Furthermore, an attacker might be able to execute arbitrary
    shell commands if "register_globals" is enabled, "magic_quotes_gpc" is
    disabled, the PHP OpenSSL extension is not installed or loaded and the
    file "installation/setup.php" has not been deleted after installation.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    phpCollab has been removed from the Portage tree. We recommend that
    users unmerge phpCollab:
    # emerge --unmerge "www-apps/phpcollab"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1495');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4303');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4304');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4305');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200812-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200812-20] phpCollab: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpCollab: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpcollab", unaffected: make_list(), vulnerable: make_list("le 2.5_rc3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
