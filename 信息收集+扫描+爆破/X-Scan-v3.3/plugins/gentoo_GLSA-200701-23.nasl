# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200701-23.xml
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
 script_id(24308);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200701-23");
 script_cve_id("CVE-2006-6799");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200701-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200701-23
(Cacti: Command execution and SQL injection)


    rgod discovered that the Cacti cmd.php and copy_cacti_user.php scripts
    do not properly control access to the command shell, and are remotely
    accessible by unauthenticated users. This allows SQL injection via
    cmd.php and copy_cacti_user.php URLs. Further, the results from the
    injected SQL query are not properly sanitized before being passed to a
    command shell. The vulnerabilities require that the
    "register_argc_argv" option is enabled, which is the Gentoo default.
    Also, a number of similar problems in other scripts were reported.
  
Impact

    These vulnerabilties can result in the execution of arbitrary shell
    commands or information disclosure via crafted SQL queries.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Cacti users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/cacti-0.8.6i-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6799');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200701-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200701-23] Cacti: Command execution and SQL injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cacti: Command execution and SQL injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/cacti", unaffected: make_list("ge 0.8.6i-r1"), vulnerable: make_list("lt 0.8.6i-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
