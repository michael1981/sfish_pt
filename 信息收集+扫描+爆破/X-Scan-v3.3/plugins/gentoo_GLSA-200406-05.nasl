# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-05.xml
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
 script_id(14516);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200406-05");
 script_cve_id("CVE-2004-0488");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-05
(Apache: Buffer overflow in mod_ssl)


    A bug in the function ssl_util_uuencode_binary in ssl_util.c may lead to a
    remote buffer overflow on a server configured to use FakeBasicAuth that
    will trust a client certificate with an issuing CA with a subject DN longer
    than 6k.
  
Impact

    Given the right server configuration, an attacker could cause a Denial of
    Service or execute code as the user running Apache, usually
    "apache". It is thought to be impossible to exploit this to
    execute code on the x86 platform, but the possibility for other platforms
    is unknown. This does not preclude a DoS on x86 systems.
  
Workaround

    A server should not be vulnerable if it is not configured to use
    FakeBasicAuth and to trust a client CA with a long subject DN.
  
');
script_set_attribute(attribute:'solution', value: '
    Apache 1.x users should upgrade to the latest version of mod_ssl:
    # emerge sync
    # emerge -pv ">=net-www/mod_ssl-2.8.18"
    # emerge ">=net-www/mod_ssl-2.8.18"
    Apache 2.x users should upgrade to the latest version of Apache:
    # emerge sync
    # emerge -pv ">=www-servers/apache-2.0.49-r3"
    # emerge ">=www-servers/apache-2.0.49-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0488');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-05] Apache: Buffer overflow in mod_ssl');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache: Buffer overflow in mod_ssl');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("lt 2.0", "ge 2.0.49-r3"), vulnerable: make_list("le 2.0.49-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-www/mod_ssl", unaffected: make_list("ge 2.8.18"), vulnerable: make_list("lt 2.8.18")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
