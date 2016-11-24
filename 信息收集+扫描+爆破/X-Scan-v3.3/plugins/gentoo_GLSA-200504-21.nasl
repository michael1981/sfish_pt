# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-21.xml
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
 script_id(18121);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200504-21");
 script_cve_id("CVE-2005-0755");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-21 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-21
(RealPlayer, Helix Player: Buffer overflow vulnerability)


    Piotr Bania has discovered a buffer overflow vulnerability in
    RealPlayer and Helix Player when processing malicious RAM files.
  
Impact

    By enticing a user to play a specially crafted RAM file an
    attacker could execute arbitrary code with the permissions of the user
    running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All RealPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/realplayer-10.0.4"
    All Helix Player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/helixplayer-1.0.4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0755');
script_set_attribute(attribute: 'see_also', value: 'http://service.real.com/help/faq/security/050419_player/EN/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-21.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-21] RealPlayer, Helix Player: Buffer overflow vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RealPlayer, Helix Player: Buffer overflow vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/realplayer", unaffected: make_list("ge 10.0.4"), vulnerable: make_list("lt 10.0.4")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-video/helixplayer", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
