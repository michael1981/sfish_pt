# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200408-18.xml
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
 script_id(14574);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200408-18");
 script_cve_id("CVE-2004-1475");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200408-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200408-18
(xine-lib: VCD MRL buffer overflow)


    xine-lib contains a bug where it is possible to overflow the vcd://
    input source identifier management buffer through carefully crafted
    playlists.
  
Impact

    An attacker may construct a carefully-crafted playlist file which will
    cause xine-lib to execute arbitrary code with the permissions of the
    user. In order to conform with the generic naming standards of most
    Unix-like systems, playlists can have extensions other than .asx (the
    standard xine playlist format), and made to look like another file
    (MP3, AVI, or MPEG for example). If an attacker crafts a playlist with
    a valid header, they can insert a VCD playlist line that can cause a
    buffer overflow and possible shellcode execution.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of xine-lib.
  
');
script_set_attribute(attribute:'solution', value: '
    All xine-lib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/xine-lib-1_rc5-r3"
    # emerge ">=media-libs/xine-lib-1_rc5-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://www.open-security.org/advisories/6');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-1475');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200408-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200408-18] xine-lib: VCD MRL buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'xine-lib: VCD MRL buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/xine-lib", unaffected: make_list("ge 1_rc5-r3"), vulnerable: make_list("le 1_rc5-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
