# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-08.xml
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
 script_id(16445);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200502-08");
 script_cve_id("CVE-2005-0227", "CVE-2005-0244", "CVE-2005-0245", "CVE-2005-0246");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-08 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-08
(PostgreSQL: Multiple vulnerabilities)


    PostgreSQL\'s contains several vulnerabilities:
    John Heasman discovered that the LOAD extension is vulnerable to
    local privilege escalation (CAN-2005-0227).
    It is possible to bypass the EXECUTE permission check for functions
    (CAN-2005-0244).
    The PL/PgSQL parser is vulnerable to heap-based buffer overflow
    (CAN-2005-0244).
    The intagg contrib module is vulnerable to a Denial of Service
    (CAN-2005-0246).
  
Impact

    An attacker could exploit this to execute arbitrary code with the
    privileges of the PostgreSQL server, bypass security restrictions and
    crash the server.
  
Workaround

    There is no know workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PostgreSQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-db/postgresql
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://archives.postgresql.org/pgsql-announce/2005-02/msg00000.php');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0227');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0244');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0245');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0246');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-08.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-08] PostgreSQL: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("eq 7.3*", "eq 7.4*", "ge 8.0.1"), vulnerable: make_list("lt 7.3.10", "lt 7.4.7", "lt 8.0.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
