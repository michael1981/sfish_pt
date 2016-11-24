# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-22.xml
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
 script_id(14533);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200406-22");
 script_cve_id("CVE-2004-0456");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-22 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-22
(Pavuk: Remote buffer overflow)


    When Pavuk connects to a web server and the server sends back the HTTP
    status code 305 (Use Proxy), Pavuk copies data from the HTTP Location
    header in an unsafe manner.
  
Impact

    An attacker could cause a stack-based buffer overflow which could lead
    to arbitrary code execution with the rights of the user running Pavuk.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version.
  
');
script_set_attribute(attribute:'solution', value: '
    All Pavuk users should upgrade to the latest stable version:
    # emerge sync
    # emerge -pv ">=net-misc/pavuk-0.9.28-r2"
    # emerge ">="net-misc/pavuk-0.9.28-r2
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0456');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-22.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-22] Pavuk: Remote buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Pavuk: Remote buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-misc/pavuk", unaffected: make_list("ge 0.9.28-r2"), vulnerable: make_list("le 0.9.28-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
