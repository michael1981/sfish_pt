# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200605-12.xml
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
 script_id(21354);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200605-12");
 script_cve_id("CVE-2006-2236");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200605-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200605-12
(Quake 3 engine based games: Buffer Overflow)


    landser discovered a vulnerability within the "remapShader"
    command. Due to a boundary handling error in "remapShader", there is a
    possibility of a buffer overflow.
  
Impact

    An attacker could set up a malicious game server and entice users
    to connect to it, potentially resulting in the execution of arbitrary
    code with the rights of the game user.
  
Workaround

    Do not connect to untrusted game servers.
  
');
script_set_attribute(attribute:'solution', value: '
    All Quake 3 users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-fps/quake3-bin-1.32c"
    All RTCW users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-fps/rtcw-1.41b"
    All Enemy Territory users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-fps/enemy-territory-2.60b"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-2236');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200605-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200605-12] Quake 3 engine based games: Buffer Overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Quake 3 engine based games: Buffer Overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-fps/quake3-bin", unaffected: make_list("ge 1.32c"), vulnerable: make_list("lt 1.32c")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "games-fps/enemy-territory", unaffected: make_list("ge 2.60b"), vulnerable: make_list("lt 2.60b")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "games-fps/rtcw", unaffected: make_list("ge 1.41b"), vulnerable: make_list("lt 1.41b")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
