# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-12.xml
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
 script_id(25208);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200705-12");
 script_cve_id("CVE-2007-2138");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-12
(PostgreSQL: Privilege escalation)


    An error involving insecure search_path settings in the SECURITY
    DEFINER functions has been reported in PostgreSQL.
  
Impact

    If allowed to call a SECURITY DEFINER function, an attacker could gain
    the SQL privileges of the owner of the called function.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PostgreSQL users should upgrade to the latest version and fix their
    SECURITY DEFINER functions:
    # emerge --sync
    # emerge --ask --oneshot --verbose "dev-db/postgresql"
    In order to fix the SECURITY DEFINER functions, PostgreSQL users are
    advised to refer to the PostgreSQL documentation: http://www.postgresql
    .org/docs/techdocs.77
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.postgresql.org/docs/techdocs.77');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-2138');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-12] PostgreSQL: Privilege escalation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Privilege escalation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("ge 8.0.13", "rge 7.4.17", "rge 7.3.19", "rge 7.3.21", "rge 7.4.19"), vulnerable: make_list("lt 8.0.13")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
