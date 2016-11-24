# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-13.xml
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
 script_id(14524);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200406-13");
 script_cve_id("CVE-2004-0541");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-13
(Squid: NTLM authentication helper buffer overflow)


    Squid is a full-featured Web Proxy Cache designed to run on Unix systems.
    It supports proxying and caching of HTTP, FTP, and other URLs, as well as
    SSL support, cache hierarchies, transparent caching, access control lists
    and many other features.
  
Impact

    If Squid is configured to use NTLM authentication, an attacker could
    exploit this vulnerability by sending a very long password. This could lead
    to arbitrary code execution with the permissions of the user running Squid.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Squid users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-proxy/squid-2.5.5-r2"
    # emerge ">=net-proxy/squid-2.5.5-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0541');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-13] Squid: NTLM authentication helper buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Squid: NTLM authentication helper buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-proxy/squid", unaffected: make_list("ge 2.5.5-r2"), vulnerable: make_list("le 2.5.5-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
