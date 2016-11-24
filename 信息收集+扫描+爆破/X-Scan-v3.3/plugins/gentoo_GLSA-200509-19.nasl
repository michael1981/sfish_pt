# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-19.xml
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
 script_id(19818);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200509-19");
 script_cve_id("CVE-2005-2491", "CVE-2005-2498");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200509-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200509-19
(PHP: Vulnerabilities in included PCRE and XML-RPC libraries)


    PHP makes use of a private copy of libpcre which is subject to an
    integer overflow leading to a heap overflow (see GLSA 200508-17). It
    also ships with an XML-RPC library affected by a script injection
    vulnerability (see GLSA 200508-13).
  
Impact

    An attacker could target a PHP-based web application that would
    use untrusted data as regular expressions, potentially resulting in the
    execution of arbitrary code. If web applications make use of the
    XML-RPC library shipped with PHP, they are also vulnerable to remote
    execution of arbitrary PHP code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php
    All mod_php users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/mod_php
    All php-cgi users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-php/php-cgi
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2491');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2498');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-13.xml');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200508-17.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200509-19] PHP: Vulnerabilities in included PCRE and XML-RPC libraries');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Vulnerabilities in included PCRE and XML-RPC libraries');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-php/php-cgi", unaffected: make_list("rge 4.3.11-r2", "ge 4.4.0-r2"), vulnerable: make_list("lt 4.4.0-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/php", unaffected: make_list("rge 4.3.11-r1", "ge 4.4.0-r1"), vulnerable: make_list("lt 4.4.0-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "dev-php/mod_php", unaffected: make_list("rge 4.3.11-r1", "ge 4.4.0-r2"), vulnerable: make_list("lt 4.4.0-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
