# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-13.xml
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
 script_id(14546);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200407-13");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-13
(PHP: Multiple security vulnerabilities)


    Several security vulnerabilities were found and fixed in version 4.3.8 of
    PHP. The strip_tags() function, used to sanitize user input, could in
    certain cases allow tags containing \\0 characters (CAN-2004-0595). When
    memory_limit is used, PHP might unsafely interrupt other functions
    (CAN-2004-0594). The ftok and itpc functions were missing safe_mode checks.
    It was possible to bypass open_basedir restrictions using MySQL\'s LOAD DATA
    LOCAL function. Furthermore, the IMAP extension was incorrectly allocating
    memory and alloca() calls were replaced with emalloc() for better stack
    protection.
  
Impact

    Successfully exploited, the memory_limit problem could allow remote
    excution of arbitrary code. By exploiting the strip_tags vulnerability, it
    is possible to pass HTML code that would be considered as valid tags by the
    Microsoft Internet Explorer and Safari browsers. Using ftok, itpc or
    MySQL\'s LOAD DATA LOCAL, it is possible to bypass PHP configuration
    restrictions.
  
Workaround

    There is no known workaround that would solve all these problems. All users
    are encouraged to upgrade to the latest available versions.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP, mod_php and php-cgi users should upgrade to the latest stable
    version:
    # emerge sync
    # emerge -pv ">=dev-php/php-4.3.8"
    # emerge ">=dev-php/php-4.3.8"
    # emerge -pv ">=dev-php/mod_php-4.3.8"
    # emerge ">=dev-php/mod_php-4.3.8"
    # emerge -pv ">=dev-php/php-cgi-4.3.8"
    # emerge ">=dev-php/php-cgi-4.3.8"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0594');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0595');
script_set_attribute(attribute: 'see_also', value: 'http://security.e-matters.de/advisories/112004.html');
script_set_attribute(attribute: 'see_also', value: 'http://security.e-matters.de/advisories/122004.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-13] PHP: Multiple security vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple security vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("ge 4.3.8"), vulnerable: make_list("le 4.3.7-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.3.8"), vulnerable: make_list("le 4.3.7-r1")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("ge 4.3.8"), vulnerable: make_list("le 4.3.7-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
