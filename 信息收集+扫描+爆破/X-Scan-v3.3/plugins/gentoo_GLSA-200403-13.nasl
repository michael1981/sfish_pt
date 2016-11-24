# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200403-13.xml
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
 script_id(14464);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200403-13");
 script_cve_id("CVE-2004-0386");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200403-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200403-13
(Remote buffer overflow in MPlayer)


    A vulnerability exists in the MPlayer HTTP parser which may allow an
    attacker to craft a special HTTP header ("Location:") which will trick
    MPlayer into executing arbitrary code on the user\'s computer.
  
Impact

    An attacker without privileges may exploit this vulnerability remotely,
    allowing arbitrary code to be executed in order to gain unauthorized
    access.
  
Workaround

    A workaround is not currently known for this issue. All users are
    advised to upgrade to the latest version of the affected package.
  
');
script_set_attribute(attribute:'solution', value: '
    MPlayer may be upgraded as follows:
    x86 and SPARC users should:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-0.92-r1"
    # emerge ">=media-video/mplayer-0.92-r1"
    AMD64 users should:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-1.0_pre2-r1"
    # emerge ">=media-video/mplayer-1.0_pre2-r1"
    PPC users should:
    # emerge sync
    # emerge -pv ">=media-video/mplayer-1.0_pre3-r2"
    # emerge ">=media-video/mplayer-1.0_pre3-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://mplayerhq.hu');
script_set_attribute(attribute: 'see_also', value: 'http://www.mplayerhq.hu/homepage/design6/news.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0386');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200403-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200403-13] Remote buffer overflow in MPlayer');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Remote buffer overflow in MPlayer');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/mplayer", arch: "ppc", unaffected: make_list("ge 1.0_pre3-r3"), vulnerable: make_list("le 1.0_pre3")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
