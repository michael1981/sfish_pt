# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-04.xml
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
 script_id(15429);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200410-04");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-04
(PHP: Memory disclosure and arbitrary location file upload)


    Stefano Di Paola discovered two bugs in PHP. The first is a parse error in
    php_variables.c that could allow a remote attacker to view the contents of
    the target machine\'s memory. Additionally, an array processing error in the
    SAPI_POST_HANDLER_FUNC() function inside rfc1867.c could lead to the
    $_FILES array being overwritten.
  
Impact

    A remote attacker could exploit the first vulnerability to view memory
    contents. On a server with a script that provides file uploads, an attacker
    could exploit the second vulnerability to upload files to an arbitrary
    location. On systems where the HTTP server is allowed to write in a
    HTTP-accessible location, this could lead to remote execution of arbitrary
    commands with the rights of the HTTP server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP, mod_php and php-cgi users should upgrade to the latest stable
    version:
    # emerge sync
    # emerge -pv ">=dev-php/php-4.3.9"
    # emerge ">=dev-php/php-4.3.9"
    # emerge -pv ">=dev-php/mod_php-4.3.9"
    # emerge ">=dev-php/mod_php-4.3.9"
    # emerge -pv ">=dev-php/php-cgi-4.3.9"
    # emerge ">=dev-php/php-cgi-4.3.9"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/12560/');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/375294');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/archive/1/375370');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-04] PHP: Memory disclosure and arbitrary location file upload');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Memory disclosure and arbitrary location file upload');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-php/php", unaffected: make_list("ge 4.3.9 "), vulnerable: make_list("lt 4.3.9")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("ge 4.3.9"), vulnerable: make_list("lt 4.3.9")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
