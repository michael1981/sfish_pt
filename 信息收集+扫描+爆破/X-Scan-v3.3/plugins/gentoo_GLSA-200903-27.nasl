# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-27.xml
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
 script_id(35917);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-27");
 script_cve_id("CVE-2009-0542", "CVE-2009-0543");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-27 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-27
(ProFTPD: Multiple vulnerabilities)


    The following vulnerabilities were reported:
    Percent characters in the username are not properly handled, which
    introduces a single quote character during variable substitution by
    mod_sql (CVE-2009-0542).
    Some invalid, encoded multibyte characters are not properly handled in
    mod_sql_mysql and mod_sql_postgres when NLS support is enabled
    (CVE-2009-0543).
  
Impact

    A remote attacker could send specially crafted requests to the server,
    possibly resulting in the execution of arbitrary SQL statements.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ProFTPD users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-ftp/proftpd-1.3.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0542');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0543');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-27.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-27] ProFTPD: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ProFTPD: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-ftp/proftpd", unaffected: make_list("ge 1.3.2"), vulnerable: make_list("lt 1.3.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
