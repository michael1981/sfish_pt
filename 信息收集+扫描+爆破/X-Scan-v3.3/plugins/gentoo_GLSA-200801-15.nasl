# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200801-15.xml
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
 script_id(30120);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200801-15");
 script_cve_id("CVE-2007-3278", "CVE-2007-4769", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-6600", "CVE-2007-6601");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200801-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200801-15
(PostgreSQL: Multiple vulnerabilities)


    If using the "expression indexes" feature, PostgreSQL executes index
    functions as the superuser during VACUUM and ANALYZE instead of the
    table owner, and allows SET ROLE and SET SESSION AUTHORIZATION in the
    index functions (CVE-2007-6600). Additionally, several errors involving
    regular expressions were found (CVE-2007-4769, CVE-2007-4772,
    CVE-2007-6067). Eventually, a privilege escalation vulnerability via
    unspecified vectors in the DBLink module was reported (CVE-2007-6601).
    This vulnerability is exploitable when local trust or ident
    authentication is used, and is due to an incomplete fix of
    CVE-2007-3278.
  
Impact

    A remote authenticated attacker could send specially crafted queries
    containing complex regular expressions to the server that could result
    in a Denial of Service by a server crash (CVE-2007-4769), an infinite
    loop (CVE-2007-4772) or a memory exhaustion (CVE-2007-6067). The two
    other vulnerabilities can be exploited to gain additional privileges.
  
Workaround

    There is no known workaround for all these issues at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PostgreSQL users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose "dev-db/postgresql"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3278');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4769');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4772');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6067');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6600');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6601');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200801-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200801-15] PostgreSQL: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("ge 8.0.15", "rge 7.4.19", "rge 7.3.21"), vulnerable: make_list("lt 8.0.15")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
