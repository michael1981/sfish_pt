# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-07.xml
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
 script_id(17263);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200503-07");
 script_cve_id("CVE-2005-0543", "CVE-2005-0544", "CVE-2005-0653");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-07
(phpMyAdmin: Multiple vulnerabilities)


    phpMyAdmin contains several security issues:
    Maksymilian Arciemowicz has discovered multiple variable injection
    vulnerabilities that can be exploited through "$cfg" and "GLOBALS"
    variables and localized strings
    It is possible to force phpMyAdmin to disclose information in error
    messages
    Failure to correctly escape special characters
  
Impact

    By sending a specially-crafted request, an attacker can include and
    execute arbitrary PHP code or cause path information disclosure.
    Furthermore the XSS issue allows an attacker to inject malicious script
    code, potentially compromising the victim\'s browser. Lastly the
    improper escaping of special characters results in unintended privilege
    settings for MySQL.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.6.1_p2-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-1');
script_set_attribute(attribute: 'see_also', value: 'http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-2');
script_set_attribute(attribute: 'see_also', value: 'http://sourceforge.net/tracker/index.php?func=detail&aid=1113788&group_id=23067&atid=377408');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0543');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0544');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0653');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-07] phpMyAdmin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.6.1_p2-r1"), vulnerable: make_list("lt 2.6.1_p2-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
