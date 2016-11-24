# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-11.xml
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
 script_id(25188);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200705-11");
 script_cve_id("CVE-2007-1420");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-11
(MySQL: Two Denial of Service vulnerabilities)


    mu-b discovered a NULL pointer dereference in item_cmpfunc.cc when
    processing certain types of SQL requests. Sec Consult also discovered
    another NULL pointer dereference when sorting certain types of queries
    on the database metadata.
  
Impact

    In both cases, a remote attacker could send a specially crafted SQL
    request to the server, possibly resulting in a server crash. Note that
    the attacker needs the ability to execute SELECT queries.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-5.0.38"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://bugs.mysql.com/bug.php?id=27513');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1420');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-11] MySQL: Two Denial of Service vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Two Denial of Service vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 5.0.38", "lt 5.0"), vulnerable: make_list("lt 5.0.38")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
