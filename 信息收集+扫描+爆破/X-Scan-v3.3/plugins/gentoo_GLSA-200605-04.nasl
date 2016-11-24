# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-04.xml
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
 script_id(21319);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200605-04");
 script_cve_id("CVE-2006-1819");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200605-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200605-04
(phpWebSite: Local file inclusion)


    rgod has reported that the "hub_dir" parameter in "index.php"
    isn\'t properly verified. When "magic_quotes_gpc" is disabled, this can
    be exploited to include arbitrary files from local ressources.
  
Impact

    If "magic_quotes_gpc" is disabled, which is not the default on
    Gentoo Linux, a remote attacker could exploit this issue to include and
    execute PHP scripts from local ressources with the rights of the user
    running the web server, or to disclose sensitive information and
    potentially compromise a vulnerable system.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpWebSite users should upgrade to the latest available
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpwebsite-0.10.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1819');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200605-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200605-04] phpWebSite: Local file inclusion');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpWebSite: Local file inclusion');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpwebsite", unaffected: make_list("ge 0.10.2"), vulnerable: make_list("lt 0.10.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
