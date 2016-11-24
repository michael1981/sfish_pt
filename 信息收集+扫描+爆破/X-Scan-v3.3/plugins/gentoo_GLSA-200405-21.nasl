# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-21.xml
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
 script_id(14507);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200405-21");
 script_cve_id("CVE-2004-0226", "CVE-2004-0231", "CVE-2004-0232");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-21
(Midnight Commander: Multiple vulnerabilities)


    Numerous security issues have been discovered in Midnight Commander,
    including several buffer overflow vulnerabilities, multiple vulnerabilities
    in the handling of temporary file and directory creation, and multiple
    format string vulnerabilities.
  
Impact

    The buffer overflows and format string vulnerabilites may allow attackers
    to cause a denial of service or execute arbitrary code with permissions of
    the user running MC. The insecure creation of temporary files and
    directories could lead to a privilege escalation, including root
    privileges, for a local attacker.
  
Workaround

    There is no known workaround at this time. All users are advised to upgrade
    to version 4.6.0-r7 or higher of Midnight Commander.
  
');
script_set_attribute(attribute:'solution', value: '
    All Midnight Commander users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=app-misc/mc-4.6.0-r7
    # emerge ">=app-misc/mc-4.6.0-r7"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0226');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0231');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0232');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-21] Midnight Commander: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Midnight Commander: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-misc/mc", unaffected: make_list("ge 4.6.0-r7"), vulnerable: make_list("le 4.6.0-r6")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
