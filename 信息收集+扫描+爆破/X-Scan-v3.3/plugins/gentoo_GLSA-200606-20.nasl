# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200606-20.xml
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
 script_id(21732);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200606-20");
 script_cve_id("CVE-2006-1515");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200606-20 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200606-20
(Typespeed: Remote execution of arbitrary code)


    Niko Tyni discovered a buffer overflow in the addnewword() function of
    Typespeed\'s network code.
  
Impact

    By sending specially crafted network packets to a machine running
    Typespeed in multiplayer mode, a remote attacker can execute arbitrary
    code with the permissions of the user running the game.
  
Workaround

    Do not run Typespeed in multiplayer mode. There is no known workaround
    at this time for multiplayer mode.
  
');
script_set_attribute(attribute:'solution', value: '
    All Typespeed users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=games-misc/typespeed-0.5.0"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1515');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200606-20.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200606-20] Typespeed: Remote execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Typespeed: Remote execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-misc/typespeed", unaffected: make_list("ge 0.5.0"), vulnerable: make_list("lt 0.5.0")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
