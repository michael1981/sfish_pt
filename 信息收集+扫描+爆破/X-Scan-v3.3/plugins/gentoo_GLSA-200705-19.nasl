# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-19.xml
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
 script_id(25340);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200705-19");
 script_cve_id("CVE-2007-1001", "CVE-2007-1285", "CVE-2007-1286", "CVE-2007-1484", "CVE-2007-1521", "CVE-2007-1583", "CVE-2007-1700", "CVE-2007-1701", "CVE-2007-1711", "CVE-2007-1717", "CVE-2007-1718", "CVE-2007-1864", "CVE-2007-1900", "CVE-2007-2509", "CVE-2007-2510", "CVE-2007-2511");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-19
(PHP: Multiple vulnerabilities)


    Several vulnerabilities were found in PHP, most of them during the
    Month Of PHP Bugs (MOPB) by Stefan Esser. The most severe of these
    vulnerabilities are integer overflows in wbmp.c from the GD library
    (CVE-2007-1001) and in the substr_compare() PHP 5 function
    (CVE-2007-1375). Ilia Alshanetsky also reported a buffer overflow in
    the make_http_soap_request() and in the user_filter_factory_create()
    functions (CVE-2007-2510, CVE-2007-2511), and Stanislav Malyshev
    discovered another buffer overflow in the bundled XMLRPC library
    (CVE-2007-1864). Additionally, the session_regenerate_id() and the
    array_user_key_compare() functions contain a double-free vulnerability
    (CVE-2007-1484, CVE-2007-1521). Finally, there exist implementation
    errors in the Zend engine, in the mb_parse_str(), the unserialize() and
    the mail() functions and other elements.
  
Impact

    Remote attackers might be able to exploit these issues in PHP
    applications making use of the affected functions, potentially
    resulting in the execution of arbitrary code, Denial of Service,
    execution of scripted contents in the context of the affected site,
    security bypass or information leak.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP 5 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-5.2.2"
    All PHP 4 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-4.4.7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1001');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1285');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1286');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1484');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1521');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1583');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1700');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1701');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1711');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1717');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1718');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1864');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1900');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2509');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2510');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2511');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-19] PHP: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/php", unaffected: make_list("rge 4.4.7", "rge 4.4.8_pre20070816", "ge 5.2.2"), vulnerable: make_list("lt 5.2.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
