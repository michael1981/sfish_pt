# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200802-02.xml
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
 script_id(30244);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200802-02");
 script_cve_id("CVE-2007-4642", "CVE-2007-4643", "CVE-2007-4644");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200802-02 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200802-02
(Doomsday: Multiple vulnerabilities)


    Luigi Auriemma discovered multiple buffer overflows in the
    D_NetPlayerEvent() function, the Msg_Write() function and the
    NetSv_ReadCommands() function. He also discovered errors when handling
    chat messages that are not NULL-terminated (CVE-2007-4642) or contain a
    short data length, triggering an integer underflow (CVE-2007-4643).
    Furthermore a format string vulnerability was discovered in the
    Cl_GetPackets() function when processing PSV_CONSOLE_TEXT messages
    (CVE-2007-4644).
  
Impact

    A remote attacker could exploit these vulnerabilities to execute
    arbitrary code with the rights of the user running the Doomsday server
    or cause a Denial of Service by sending specially crafted messages to
    the server.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    While some of these issues could be resolved in
    "games-fps/doomsday-1.9.0-beta5.2", the format string vulnerability
    (CVE-2007-4644) remains unfixed. We recommend that users unmerge
    Doomsday:
    # emerge --unmerge games-fps/doomsday
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4642');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4643');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4644');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200802-02.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200802-02] Doomsday: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Doomsday: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "games-fps/doomsday", unaffected: make_list(), vulnerable: make_list("le 1.9.0_beta52")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
