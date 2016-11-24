# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-18.xml
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
 script_id(20262);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200511-18");
 script_cve_id("CVE-2005-3347", "CVE-2005-3348");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-18
(phpSysInfo: Multiple vulnerabilities)


    Christopher Kunz from the Hardened-PHP Project discovered
    that phpSysInfo is vulnerable to local file inclusion, cross-site
    scripting and a HTTP Response Splitting attacks.
  
Impact

    A local attacker may exploit the file inclusion vulnerability by
    sending malicious requests, causing the execution of arbitrary code
    with the rights of the user running the web server. A remote attacker
    could exploit the vulnerability to disclose local file content.
    Furthermore, the cross-site scripting issues gives a remote attacker
    the ability to inject and execute malicious script code in the user\'s
    browser context or to steal cookie-based authentication credentials.
    The HTTP response splitting issue give an attacker the ability to
    perform site hijacking and cache poisoning.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpSysInfo users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/phpsysinfo-2.4.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory_222005.81.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3347');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3348');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-18] phpSysInfo: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpSysInfo: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/phpsysinfo", unaffected: make_list("ge 2.4.1"), vulnerable: make_list("lt 2.4.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
