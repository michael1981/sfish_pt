# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200906-03.xml
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
 script_id(39570);
 script_version("$Revision: 1.1 $");
 script_xref(name: "GLSA", value: "200906-03");
 script_cve_id("CVE-2009-1150", "CVE-2009-1151");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200906-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200906-03
(phpMyAdmin: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in phpMyAdmin:
    Greg Ose discovered that the setup script does not sanitize input
    properly, leading to the injection of arbitrary PHP code into the
    configuration file (CVE-2009-1151).
    Manuel Lopez Gallego and
    Santiago Rodriguez Collazo reported that data from cookies used in the
    "Export" page is not properly sanitized (CVE-2009-1150).
  
Impact

    A remote unauthorized attacker could exploit the first vulnerability to
    execute arbitrary code with the privileges of the user running
    phpMyAdmin and conduct Cross-Site Scripting attacks using the second
    vulnerability.
  
Workaround

    Removing the "scripts/setup.php" file protects you from CVE-2009-1151.
  
');
script_set_attribute(attribute:'solution', value: '
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.11.9.5"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1150');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1151');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200906-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200906-03] phpMyAdmin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.11.9.5"), vulnerable: make_list("lt 2.11.9.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
