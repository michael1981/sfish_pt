# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200908-09.xml
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
 script_id(40634);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200908-09");
 script_cve_id("CVE-2009-1960");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200908-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200908-09
(DokuWiki: Local file inclusion)


    girex reported that data from the "config_cascade" parameter in
    inc/init.php is not properly sanitized before being used.
  
Impact

    A remote attacker could exploit this vulnerability to execute PHP code
    from arbitrary local, or, when the used PHP version supports ftp://
    URLs, also from remote files via FTP. Furthermore, it is possible to
    disclose the contents of local files. NOTE: Successful exploitation
    requires the PHP option "register_globals" to be enabled.
  
Workaround

    Disable "register_globals" in php.ini.
  
');
script_set_attribute(attribute:'solution', value: '
    All DokuWiki users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose =www-apps/dokuwiki-2009-02-14b
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1960');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200908-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200908-09] DokuWiki: Local file inclusion');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'DokuWiki: Local file inclusion');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/dokuwiki", unaffected: make_list("ge 20090214b"), vulnerable: make_list("lt 20090214b")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
