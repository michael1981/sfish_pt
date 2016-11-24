# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200708-08.xml
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
 script_id(25873);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200708-08");
 script_cve_id("CVE-2005-1924", "CVE-2006-4169");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200708-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200708-08
(SquirrelMail G/PGP plugin: Arbitrary code execution)


    The functions deletekey(), gpg_check_sign_pgp_mime() and gpg_recv_key()
    used in the SquirrelMail G/PGP encryption plugin do not properly escape
    user-supplied data.
  
Impact

    An authenticated user could use the plugin to execute arbitrary code on
    the server, or a remote attacker could send a specially crafted e-mail
    to a SquirrelMail user, possibly leading to the execution of arbitrary
    code with the privileges of the user running the underlying web server.
    Note that the G/PGP plugin is disabled by default.
  
Workaround

    Enter the SquirrelMail configuration directory
    (/usr/share/webapps/squirrelmail/version/htdocs/config), then execute
    the conf.pl script. Select the plugins menu, then select the gpg plugin
    item number in the "Installed Plugins" list to disable it. Press S to
    save your changes, then Q to quit.
  
');
script_set_attribute(attribute:'solution', value: '
    All SquirrelMail users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=mail-client/squirrelmail-1.4.10a-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1924');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4169');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200708-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200708-08] SquirrelMail G/PGP plugin: Arbitrary code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SquirrelMail G/PGP plugin: Arbitrary code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/squirrelmail", unaffected: make_list("ge 1.4.10a-r2"), vulnerable: make_list("lt 1.4.10a-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
