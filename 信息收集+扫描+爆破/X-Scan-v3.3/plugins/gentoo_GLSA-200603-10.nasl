# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200603-10.xml
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
 script_id(21048);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200603-10");
 script_cve_id("CVE-2006-1100", "CVE-2006-1101", "CVE-2006-1102");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200603-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200603-10
(Cube: Multiple vulnerabilities)


    Luigi Auriemma reported that Cube is vulnerable to a buffer
    overflow in the sgetstr() function (CVE-2006-1100) and that the
    sgetstr() and getint() functions fail to verify the length of the
    supplied argument, possibly leading to the access of invalid memory
    regions (CVE-2006-1101). Furthermore, he discovered that a client
    crashes when asked to load specially crafted mapnames (CVE-2006-1102).
  
Impact

    A remote attacker could exploit the buffer overflow to execute
    arbitrary code with the rights of the user running cube. An attacker
    could also exploit the other vulnerabilities to crash a Cube client or
    server, resulting in a Denial of Service.
  
Workaround

    Play solo games or restrict your multiplayer games to trusted
    parties.
  
');
script_set_attribute(attribute:'solution', value: '
    Upstream stated that there will be no fixed version of Cube, thus
    the Gentoo Security Team decided to hardmask Cube for security reasons.
    All Cube users are encouraged to uninstall Cube:
    # emerge --ask --unmerge games-fps/cube
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1100');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1101');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-1102');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200603-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200603-10] Cube: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Cube: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-fps/cube", unaffected: make_list(), vulnerable: make_list("le 20050829")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
