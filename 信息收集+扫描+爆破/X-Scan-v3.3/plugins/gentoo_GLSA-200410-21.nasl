# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-21.xml
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
 script_id(15545);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200410-21");
 script_cve_id("CVE-2004-0885");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-21
(Apache 2, mod_ssl: Bypass of SSLCipherSuite directive)


    A flaw has been found in mod_ssl where the "SSLCipherSuite" directive could
    be bypassed in certain configurations if it is used in a directory or
    location context to restrict the set of allowed cipher suites.
  
Impact

    A remote attacker could gain access to a location using any cipher suite
    allowed by the server/virtual host configuration, disregarding the
    restrictions by "SSLCipherSuite" for that location.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Apache 2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=www-servers/apache-2.0.52"
    # emerge ">=www-servers/apache-2.0.52"
    All mod_ssl users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=net-www/mod_ssl-2.8.20"
    # emerge ">=net-www/mod_ssl-2.8.20"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0885');
script_set_attribute(attribute: 'see_also', value: 'http://issues.apache.org/bugzilla/show_bug.cgi?id=31505');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-21] Apache 2, mod_ssl: Bypass of SSLCipherSuite directive');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache 2, mod_ssl: Bypass of SSLCipherSuite directive');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 2.0.52", "lt 2.0"), vulnerable: make_list("lt 2.0.52")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-www/mod_ssl", unaffected: make_list("ge 2.8.20"), vulnerable: make_list("lt 2.8.20")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
