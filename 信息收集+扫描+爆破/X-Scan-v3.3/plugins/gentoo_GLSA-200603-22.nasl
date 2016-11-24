# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-22.xml
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
 script_id(21129);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-22");
 script_cve_id("CVE-2006-0207", "CVE-2006-0208");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-22
(PHP: Format string and XSS vulnerabilities)


    Stefan Esser of the Hardened PHP project has reported a few
    vulnerabilities found in PHP:
    Input passed to the session
    ID in the session extension isn\'t properly sanitised before being
    returned to the user via a "Set-Cookie" HTTP header, which can contain
    arbitrary injected data.
    A format string error while
    processing error messages using the mysqli extension in version 5.1 and
    above.
  
Impact

    By sending a specially crafted request, a remote attacker can
    exploit this vulnerability to inject arbitrary HTTP headers, which will
    be included in the response sent to the user. The format string
    vulnerability may be exploited to execute arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PHP 5.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-5.1.2"
    All PHP 4.x users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/php-4.4.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0207');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0208');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory_022006.112.html');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory_012006.113.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-22] PHP: Format string and XSS vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PHP: Format string and XSS vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/php", unaffected: make_list("ge 5.1.2"), vulnerable: make_list("lt 4.4.2", "rge 5.1.1", "rge 5.0.5", "rge 5.0.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
