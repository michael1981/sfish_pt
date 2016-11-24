# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200607-04.xml
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
 script_id(22011);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200607-04");
 script_cve_id("CVE-2006-2313", "CVE-2006-2314");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200607-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200607-04
(PostgreSQL: SQL injection)


    PostgreSQL contains a flaw in the string parsing routines that allows
    certain backslash-escaped characters to be bypassed with some multibyte
    character encodings. This vulnerability was discovered by Akio Ishida
    and Yasuo Ohgaki.
  
Impact

    An attacker could execute arbitrary SQL statements on the PostgreSQL
    server. Be aware that web applications using PostgreSQL as a database
    back-end might be used to exploit this vulnerability.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All PostgreSQL users should upgrade to the latest version in the
    respective branch they are using:
    # emerge --sync
    # emerge --ask --oneshot --verbose dev-db/postgresql
    Note: While a fix exists for the 7.3 branch it doesn\'t currently work
    on Gentoo. All 7.3.x users of PostgreSQL should consider updating their
    installations to the 7.4 (or higher) branch as soon as possible!
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.postgresql.org/docs/techdocs.50');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2313');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2314');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200607-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200607-04] PostgreSQL: SQL injection');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'PostgreSQL: SQL injection');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-db/postgresql", unaffected: make_list("ge 8.0.8", "eq 7.4*"), vulnerable: make_list("lt 8.0.8", "lt 7.4.13")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
