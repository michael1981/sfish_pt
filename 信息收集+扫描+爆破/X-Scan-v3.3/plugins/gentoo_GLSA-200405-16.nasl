# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-16.xml
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
 script_id(14502);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-16");
 script_cve_id("CVE-2004-0519", "CVE-2004-0521");
 script_xref(name: "CERT", value: "CA-2000-02");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-16 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-16
(Multiple XSS Vulnerabilities in SquirrelMail)


    Several unspecified cross-site scripting (XSS) vulnerabilities and a
    well hidden SQL injection vulnerability were found. An XSS attack
    allows an attacker to insert malicious code into a web-based
    application. SquirrelMail does not check for code when parsing
    variables received via the URL query string.
  
Impact

    One of the XSS vulnerabilities could be exploited by an attacker to
    steal cookie-based authentication credentials from the user\'s browser.
    The SQL injection issue could potentially be used by an attacker to run
    arbitrary SQL commands inside the SquirrelMail database with privileges
    of the SquirrelMail database user.
  
Workaround

    There is no known workaround at this time. All users are advised to
    upgrade to version 1.4.3_rc1 or higher of SquirrelMail.
  
');
script_set_attribute(attribute:'solution', value: '
    All SquirrelMail users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=mail-client/squirrelmail-1.4.3_rc1"
    # emerge ">=mail-client/squirrelmail-1.4.3_rc1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/mailarchive/forum.php?thread_id=4199060&forum_id=1988');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/10246/');
script_set_attribute(attribute: 'see_also', value: 'http://www.cert.org/advisories/CA-2000-02.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0519');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0521');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-16.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-16] Multiple XSS Vulnerabilities in SquirrelMail');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple XSS Vulnerabilities in SquirrelMail');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "mail-client/squirrelmail", unaffected: make_list("ge 1.4.3_rc1"), vulnerable: make_list("lt 1.4.3_rc1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
