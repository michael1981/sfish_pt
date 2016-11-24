# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200506-04.xml
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
 script_id(18427);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200506-04");
 script_cve_id("CVE-2005-1102", "CVE-2005-1687", "CVE-2005-1810");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200506-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200506-04
(Wordpress: Multiple vulnerabilities)


    Due to a lack of input validation, WordPress is vulnerable to SQL
    injection and XSS attacks.
  
Impact

    An attacker could use the SQL injection vulnerabilites to gain
    information from the database. Furthermore the cross-site scripting
    issues give an attacker the ability to inject and execute malicious
    script code or to steal cookie-based authentication credentials,
    potentially compromising the victim\'s browser.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wordpress users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-apps/wordpress-1.5.1.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1102');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1687');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1810');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200506-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200506-04] Wordpress: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wordpress: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/wordpress", unaffected: make_list("ge 1.5.1.2"), vulnerable: make_list("lt 1.5.1.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
