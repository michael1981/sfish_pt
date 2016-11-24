# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-19.xml
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
 script_id(16460);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-19");
 script_cve_id("CVE-2005-0247");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-19 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-19
(PostgreSQL: Buffer overflows in PL/PgSQL parser)


    PostgreSQL is vulnerable to several buffer overflows in the PL/PgSQL
    parser.
  
Impact

    A remote attacker could send a malicious query resulting in the
    execution of arbitrary code with the permissions of the user running
    PostgreSQL.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PostgreSQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-db/postgresql
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0247');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-19.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-19] PostgreSQL: Buffer overflows in PL/PgSQL parser');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Buffer overflows in PL/PgSQL parser');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("eq 7.3*", "eq 7.4*", "ge 8.0.1-r1"), vulnerable: make_list("lt 7.3.9-r1", "lt 7.4.13", "lt 8.0.1-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
