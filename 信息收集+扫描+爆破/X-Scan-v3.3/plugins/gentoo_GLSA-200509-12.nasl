# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200509-12.xml
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
 script_id(19811);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200509-12");
 script_cve_id("CVE-2005-2491", "CVE-2005-2700");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200509-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200509-12
(Apache, mod_ssl: Multiple vulnerabilities)


    mod_ssl contains a security issue when "SSLVerifyClient optional" is
    configured in the global virtual host configuration (CAN-2005-2700).
    Also, Apache\'s httpd includes a PCRE library, which makes it vulnerable
    to an integer overflow (CAN-2005-2491).
  
Impact

    Under a specific configuration, mod_ssl does not properly enforce the
    client-based certificate authentication directive, "SSLVerifyClient
    require", in a per-location context, which could be potentially used by
    a remote attacker to bypass some restrictions. By creating a specially
    crafted ".htaccess" file, a local attacker could possibly exploit
    Apache\'s vulnerability, which would result in a local privilege
    escalation.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All mod_ssl users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-www/mod_ssl-2.8.24"
    All Apache 2 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=www-servers/apache-2.0.54-r15"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2491');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2700');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200509-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200509-12] Apache, mod_ssl: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Apache, mod_ssl: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-servers/apache", unaffected: make_list("ge 2.0.54-r15", "lt 2"), vulnerable: make_list("lt 2.0.54-r15")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "net-www/mod_ssl", unaffected: make_list("ge 2.8.24"), vulnerable: make_list("lt 2.8.24")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
