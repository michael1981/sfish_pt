# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-14.xml
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
 script_id(14465);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200403-14");
 script_cve_id("CVE-2003-1083", "CVE-2003-1084");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-14
(Multiple Security Vulnerabilities in Monit)


    A denial of service may occur due to Monit not sanitizing remotely
    supplied HTTP parameters before passing them to memory allocation
    functions. This could allow an attacker to cause an unexpected
    condition that could lead to the Monit daemon crashing.
    An overly long http request method may cause a buffer overflow due to
    Monit performing insufficient bounds checking when handling HTTP
    requests.
  
Impact

    An attacker may crash the Monit daemon to create a denial of service
    condition or cause a buffer overflow that would allow arbitrary code to
    be executed with root privileges.
  
Workaround

    A workaround is not currently known for this issue. All users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    Monit users should upgrade to version 4.2 or later:
    # emerge sync
    # emerge -pv ">=app-admin/monit-4.2"
    # emerge ">=app-admin/monit-4.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/9098');
script_set_attribute(attribute: 'see_also', value: 'http://www.securityfocus.com/bid/9099');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1083');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1084');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-14] Multiple Security Vulnerabilities in Monit');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Multiple Security Vulnerabilities in Monit');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-admin/monit", unaffected: make_list("ge 4.2"), vulnerable: make_list("le 4.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
