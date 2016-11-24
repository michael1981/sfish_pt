# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200406-09.xml
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
 script_id(14520);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200406-09");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200406-09 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200406-09
(Horde-Chora: Remote code execution)


    A vulnerability in the diff viewer of Chora allows an attacker to inject
    shellcode. An attacker can exploit PHP\'s file upload functionality to
    upload a malicious binary to a vulnerable server, chmod it as executable,
    and run the file.
  
Impact

    An attacker could remotely execute arbitrary binaries with the permissions
    of the PHP script, conceivably allowing further exploitation of local
    vulnerabilities and remote root access.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All users are advised to upgrade to the latest version of Chora:
    # emerge sync
    # emerge -pv ">=www-apps/horde-chora-1.2.2"
    # emerge ">=www-apps/horde-chora-1.2.2"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_set_attribute(attribute: 'see_also', value: 'http://security.e-matters.de/advisories/102004.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200406-09.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200406-09] Horde-Chora: Remote code execution');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Horde-Chora: Remote code execution');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "www-apps/horde-chora", unaffected: make_list("ge 1.2.2"), vulnerable: make_list("lt 1.2.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
