# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200405-24.xml
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
 script_id(14510);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200405-24");
 script_cve_id("CVE-2004-0433");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200405-24 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200405-24
(MPlayer, xine-lib: vulnerabilities in RTSP stream handling)


    Multiple vulnerabilities have been found and fixed in the RTSP handling
    code common to recent versions of these two packages. These vulnerabilities
    include several remotely exploitable buffer overflows.
  
Impact

    A remote attacker, posing as a RTSP stream server, can execute arbitrary
    code with the rights of the user of the software playing the stream
    (MPlayer or any player using xine-lib). Another attacker may entice a user
    to use a maliciously crafted URL or playlist to achieve the same results.
  
Workaround

    For MPlayer, there is no known workaround at this time. For xine-lib, you
    can delete the xineplug_inp_rtsp.so file.
  
');
script_set_attribute(attribute:'solution', value: '
    All users should upgrade to non-vulnerable versions of MPlayer and
    xine-lib:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-1.0_pre4"
    # emerge ">=media-video/mplayer-1.0_pre4"
    # emerge -pv ">=media-libs/xine-lib-1_rc4"
    # emerge ">=media-libs/xine-lib-1_rc4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://xinehq.de/index.php/security/XSA-2004-3');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0433');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200405-24.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200405-24] MPlayer, xine-lib: vulnerabilities in RTSP stream handling');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer, xine-lib: vulnerabilities in RTSP stream handling');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1_rc4", "le 0.9.13-r3"), vulnerable: make_list("lt 1_rc4")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_pre4", "le 0.92-r1"), vulnerable: make_list("lt 1.0_pre4")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
