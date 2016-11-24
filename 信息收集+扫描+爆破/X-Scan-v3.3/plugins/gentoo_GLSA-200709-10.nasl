# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-10.xml
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
 script_id(26100);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200709-10");
 script_cve_id("CVE-2007-3193");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-10
(PhpWiki: Authentication bypass)


    The PhpWiki development team reported an authentication error within
    the file lib/WikiUser/LDAP.php when binding to an LDAP server with an
    empty password.
  
Impact

    A remote attacker could provide an empty password when authenticating.
    Depending on the LDAP implementation used, this could bypass the
    PhpWiki authentication mechanism and grant the attacker access to the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PhpWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpwiki-1.3.14"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3193');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-10] PhpWiki: Authentication bypass');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PhpWiki: Authentication bypass');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpwiki", unaffected: make_list("ge 1.3.14"), vulnerable: make_list("lt 1.3.14")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
