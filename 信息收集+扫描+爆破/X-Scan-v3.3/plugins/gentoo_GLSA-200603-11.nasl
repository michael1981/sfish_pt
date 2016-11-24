# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-11.xml
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
 script_id(21084);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-11");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-11
(Freeciv: Denial of Service)


    Luigi Auriemma discovered that Freeciv could be tricked into the
    allocation of enormous chunks of memory when trying to uncompress
    malformed data packages, possibly leading to an out of memory condition
    which causes Freeciv to crash or freeze.
  
Impact

    A remote attacker could exploit this issue to cause a Denial of
    Service by sending specially crafted data packages to the Freeciv game
    server.
  
Workaround

    Play solo games or restrict your multiplayer games to trusted
    parties.
  
');
script_set_attribute(attribute:'solution', value: '
    All Freeciv users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-strategy/freeciv-2.0.8"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-0047');
script_set_attribute(attribute: 'see_also', value: 'http://aluigi.altervista.org/adv/freecivdos-adv.txt');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-11] Freeciv: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Freeciv: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-strategy/freeciv", unaffected: make_list("ge 2.0.8"), vulnerable: make_list("lt 2.0.8")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
