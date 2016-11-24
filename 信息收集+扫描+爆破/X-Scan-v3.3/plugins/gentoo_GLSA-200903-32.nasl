# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-32.xml
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
 script_id(35964);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200903-32");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-32 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-32
(phpMyAdmin: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in phpMyAdmin:
    libraries/database_interface.lib.php in phpMyAdmin allows remote
    authenticated users to execute arbitrary code via a request to
    server_databases.php with a sort_by parameter containing PHP sequences,
    which are processed by create_function (CVE-2008-4096).
    Cross-site scripting (XSS) vulnerability in pmd_pdf.php allows remote
    attackers to inject arbitrary web script or HTML via the db parameter,
    a different vector than CVE-2006-6942 and CVE-2007-5977
    (CVE-2008-4775).
    Cross-site request forgery (CSRF) vulnerability in phpMyAdmin allows
    remote authenticated attackers to perform unauthorized actions as the
    administrator via a link or IMG tag to tbl_structure.php with a
    modified table parameter. NOTE: this can be leveraged to conduct SQL
    injection attacks and execute arbitrary code (CVE-2008-5621).
    Multiple cross-site request forgery (CSRF) vulnerabilities in
    phpMyAdmin allow remote attackers to conduct SQL injection attacks via
    unknown vectors related to the table parameter, a different vector than
    CVE-2008-5621 (CVE-2008-5622).
  
Impact

    A remote attacker may execute arbitrary code with the rights of the
    webserver, inject and execute SQL with the rights of phpMyAdmin or
    conduct XSS attacks against other users.
  
Workaround

    There is no known workaround at this time.
  
References:
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6942
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5977
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4096
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4775
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5621
    http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5622

');
script_set_attribute(attribute:'solution', value: '
    All phpMyAdmin users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/phpmyadmin-2.11.9.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-32.xml');
script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-32] phpMyAdmin: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_cve_id("CVE-2006-6942", "CVE-2007-5977", "CVE-2008-4096", "CVE-2008-4775", "CVE-2008-5621");
 script_summary(english: 'phpMyAdmin: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/phpmyadmin", unaffected: make_list("ge 2.11.9.4"), vulnerable: make_list("lt 2.11.9.4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
