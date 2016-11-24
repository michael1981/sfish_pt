# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200511-12.xml
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
 script_id(20233);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200511-12");
 script_cve_id("CVE-2005-3486", "CVE-2005-3487", "CVE-2005-3488");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200511-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200511-12
(Scorched 3D: Multiple vulnerabilities)


    Luigi Auriemma discovered multiple flaws in the Scorched 3D game
    server, including a format string vulnerability and several buffer
    overflows.
  
Impact

    A remote attacker can exploit these vulnerabilities to crash a game
    server or execute arbitrary code with the rights of the game server
    user. Users not running a Scorched 3D game server are not affected by
    these flaws.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Scorched 3D users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-strategy/scorched3d-40"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://seclists.org/lists/fulldisclosure/2005/Nov/0079.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3486');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3487');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3488');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200511-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200511-12] Scorched 3D: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Scorched 3D: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-strategy/scorched3d", unaffected: make_list("ge 40"), vulnerable: make_list("le 39.1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
