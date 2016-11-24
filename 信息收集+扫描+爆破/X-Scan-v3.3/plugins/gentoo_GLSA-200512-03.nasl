# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200512-03.xml
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
 script_id(20312);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200512-03");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200512-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200512-03
(phpMyAdmin: Multiple vulnerabilities)


    Stefan Esser from Hardened-PHP reported about multiple
    vulnerabilties found in phpMyAdmin. The $GLOBALS variable allows
    modifying the global variable import_blacklist to open phpMyAdmin to
    local and remote file inclusion, depending on your PHP version
    (CVE-2005-4079, PMASA-2005-9). Furthermore, it is also possible to
    conduct an XSS attack via the $HTTP_HOST variable and a local and
    remote file inclusion because the contents of the variable are under
    total control of the attacker (CVE-2005-3665, PMASA-2005-8).
  
Impact

    A remote attacker may exploit these vulnerabilities by sending
    malicious requests, causing the execution of arbitrary code with the
    rights of the user running the web server. The cross-site scripting
    issues allow a remote attacker to inject and execute malicious script
    code or to steal cookie-based authentication credentials, potentially
    allowing unauthorized access to phpMyAdmin.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.7.0_p1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3665');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4079');
script_set_attribute(attribute: 'see_also', value: 'http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-8');
script_set_attribute(attribute: 'see_also', value: 'http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2005-9');
script_set_attribute(attribute: 'see_also', value: 'http://www.hardened-php.net/advisory_252005.110.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200512-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200512-03] phpMyAdmin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.7.0_p1"), vulnerable: make_list("lt 2.7.0_p1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
