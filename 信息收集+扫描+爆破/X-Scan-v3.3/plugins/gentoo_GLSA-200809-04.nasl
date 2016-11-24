# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200809-04.xml
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
 script_id(34093);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200809-04");
 script_cve_id("CVE-2008-2079");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200809-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200809-04
(MySQL: Privilege bypass)


    Sergei Golubchik reported that MySQL imposes no restrictions on the
    specification of "DATA DIRECTORY" or "INDEX DIRECTORY" in SQL "CREATE
    TABLE" statements.
  
Impact

    An authenticated remote attacker could create MyISAM tables, specifying
    DATA or INDEX directories that contain future table files by other
    database users, or existing table files in the MySQL data directory,
    gaining access to those tables.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MySQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-db/mysql-5.0.60-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-2079');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200809-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200809-04] MySQL: Privilege bypass');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MySQL: Privilege bypass');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/mysql", unaffected: make_list("ge 5.0.60-r1"), vulnerable: make_list("lt 5.0.60-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
