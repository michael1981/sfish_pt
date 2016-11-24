# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-15.xml
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
 script_id(24840);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200703-15");
 script_cve_id("CVE-2007-0555", "CVE-2007-0556");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-15
(PostgreSQL: Multiple vulnerabilities)


    PostgreSQL does not correctly check the data types of the SQL function
    arguments under unspecified circumstances nor the format of the
    provided tables in the query planner.
  
Impact

    A remote authenticated attacker could send specially crafted queries to
    the server that could result in a server crash and possibly the
    unauthorized reading of some database content or arbitrary memory.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PostgreSQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "dev-db/postgresql"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0555');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0556');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-15] PostgreSQL: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("ge 8.0.11", "rge 7.4.17", "rge 7.4.16", "rge 7.3.19", "rge 7.3.13", "rge 7.3.21", "rge 7.4.19"), vulnerable: make_list("lt 8.0.11")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
