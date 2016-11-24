# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-12.xml
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
 script_id(35406);
 script_version("$Revision: 1.3 $");
 script_xref(name: "GLSA", value: "200901-12");
 script_cve_id("CVE-2008-5297");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-12
(noip-updater: Execution of arbitrary code)


    xenomuta found out that the GetNextLine() function in noip2.c misses a
    length check, leading to a stack-based buffer overflow.
  
Impact

    A remote attacker could exploit this vulnerability to execute arbitrary
    code by sending a specially crafted HTTP message to the client. NOTE:
    Successful exploitation requires a man in the middle attack, a DNS
    spoofing attack or a compromise of no-ip.com servers.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All noip-updater users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-dns/noip-updater-2.1.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5297');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-12] noip-updater: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'noip-updater: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-dns/noip-updater", unaffected: make_list("ge 2.1.9"), vulnerable: make_list("lt 2.1.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
