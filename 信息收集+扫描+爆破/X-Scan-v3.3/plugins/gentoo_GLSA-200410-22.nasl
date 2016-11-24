# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-22.xml
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
 script_id(15558);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200410-22");
 script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-22
(MySQL: Multiple vulnerabilities)


    The following vulnerabilities were found and fixed in MySQL:
    Oleksandr Byelkin found that ALTER TABLE ... RENAME checks CREATE/INSERT
    rights of the old table instead of the new one (CAN-2004-0835). Another
    privilege checking bug allowed users to grant rights on a database they had
    no rights on.
    Dean Ellis found a defect where multiple threads ALTERing the MERGE tables
    to change the UNION could cause the server to crash (CAN-2004-0837).
    Another crash was found in MATCH ... AGAINST() queries with missing closing
    double quote.
    Finally, a buffer overrun in the mysql_real_connect function was found by
    Lukasz Wojtow (CAN-2004-0836).
  
Impact

    The privilege checking issues could be used by remote users to bypass their
    rights on databases. The two crashes issues could be exploited by a remote
    user to perform a Denial of Service attack on MySQL server. The buffer
    overrun issue could also be exploited as a Denial of Service attack, and
    may allow to execute arbitrary code with the rights of the MySQL daemon
    (typically, the "mysql" user).
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MySQL users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=dev-db/mysql-4.0.21"
    # emerge ">=dev-db/mysql-4.0.21"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0835');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0836');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0837');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.mysql.com/bug.php?id=3933');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.mysql.com/bug.php?id=3870');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-22] MySQL: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 4.0.21"), vulnerable: make_list("lt 4.0.21")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
