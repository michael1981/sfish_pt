# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-22.xml
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
 script_id(14555);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-22");
 script_cve_id("CVE-2004-2631", "CVE-2004-2632");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-22
(phpMyAdmin: Multiple vulnerabilities)


    Two serious vulnerabilities exist in phpMyAdmin. The first allows any
    user to alter the server configuration variables (including host, name,
    and password) by appending new settings to the array variables that
    hold the configuration in a GET statement. The second allows users to
    include arbitrary PHP code to be executed within an eval() statement in
    table name configuration settings. This second vulnerability is only
    exploitable if $cfg[\'LeftFrameLight\'] is set to FALSE.
  
Impact

    Authenticated users can alter configuration variables for their running
    copy of phpMyAdmin. The impact of this should be minimal. However, the
    second vulnerability would allow an authenticated user to execute
    arbitrary PHP code with the permissions of the webserver, potentially
    allowing a serious Denial of Service or further remote compromise.
  
Workaround

    The second, more serious vulnerability is only exploitable if
    $cfg[\'LeftFrameLight\'] is set to FALSE. In the default Gentoo
    installation, this is set to TRUE. There is no known workaround for the
    first.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpMyAdmin users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-db/phpmyadmin-2.5.7_p1"
    # emerge ">=dev-db/phpmyadmin-2.5.7_p1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/367486');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2631');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2632');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-22] phpMyAdmin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.5.7_p1"), vulnerable: make_list("le 2.5.7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
