# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-14.xml
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
 script_id(14547);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-14");
 script_cve_id("CVE-2004-0608");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-14
(Unreal Tournament 2003/2004: Buffer overflow in \'secure\' queries)


    The Unreal-based game servers support a specific type of query called
    \'secure\'. Part of the Gamespy protocol, this query is used to ask if the
    game server is able to calculate an exact response using a provided string.
    Luigi Auriemma found that sending a long \'secure\' query triggers a buffer
    overflow in the game server.
  
Impact

    By sending a malicious UDP-based \'secure\' query, an attacker could execute
    arbitrary code on the game server.
  
Workaround

    Users can avoid this vulnerability by not using Unreal Tournament to host
    games as a server. All users running a server should upgrade to the latest
    versions.
  
');
script_set_attribute(attribute:'solution', value: '
    All Unreal Tournament users should upgrade to the latest available
    versions:
    # emerge sync
    # emerge -pv ">=games-fps/ut2003-2225-r3"
    # emerge ">=games-fps/ut2003-2225-r3"
    # emerge -pv ">=games-server/ut2003-ded-2225-r2"
    # emerge ">=games-server/ut2003-ded-2225-r2"
    # emerge -pv ">=games-fps/ut2004-3236"
    # emerge ">=games-fps/ut2004-3236"
    # emerge -pv ">=games-fps/ut2004-demo-3120-r4"
    # emerge ">=games-fps/ut2004-demo-3120-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://aluigi.altervista.org/adv/unsecure-adv.txt');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0608');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-14] Unreal Tournament 2003/2004: Buffer overflow in \'secure\' queries');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Unreal Tournament 2003/2004: Buffer overflow in \'secure\' queries');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-fps/ut2004-demo", unaffected: make_list("ge 3120-r4"), vulnerable: make_list("le 3120-r3")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "games-fps/ut2004", unaffected: make_list("ge 3236"), vulnerable: make_list("lt 3236")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "games-server/ut2003-ded", unaffected: make_list("ge 2225-r2"), vulnerable: make_list("le 2225-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "games-fps/ut2003", unaffected: make_list("ge 2225-r3"), vulnerable: make_list("le 2225-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
