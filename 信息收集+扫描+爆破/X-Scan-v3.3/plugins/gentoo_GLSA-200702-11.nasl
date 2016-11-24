# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200702-11.xml
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
 script_id(24731);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200702-11");
 script_cve_id("CVE-2006-6172");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200702-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200702-11
(MPlayer: Buffer overflow)


    When checking for matching asm rules in the asmrp.c code, the results
    are stored in a fixed-size array without boundary checks which may
    allow a buffer overflow.
  
Impact

    An attacker can entice a user to connect to a manipulated RTSP server
    resulting in a Denial of Service and possibly execution of arbitrary
    code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mplayer-1.0_rc1-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.mplayerhq.hu/design7/news.html#vuln14');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6172');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200702-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200702-11] MPlayer: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_rc1-r2"), vulnerable: make_list("lt 1.0_rc1-r2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
