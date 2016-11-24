# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200510-07.xml
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
 script_id(19977);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200510-07");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200510-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200510-07
(RealPlayer, Helix Player: Format string vulnerability)


    "c0ntex" reported that RealPlayer and Helix Player suffer from a heap
    overflow.
  
Impact

    By enticing a user to play a specially crafted realpix (.rp) or
    realtext (.rt) file, an attacker could execute arbitrary code with the
    permissions of the user running the application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All RealPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/realplayer-10.0.6"
    Note to Helix Player users: There is currently no stable secure Helix
    Player package. Affected users should remove the package until an
    updated Helix Player package is released.
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-2710');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200510-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200510-07] RealPlayer, Helix Player: Format string vulnerability');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RealPlayer, Helix Player: Format string vulnerability');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/realplayer", unaffected: make_list("ge 10.0.6"), vulnerable: make_list("lt 10.0.6")
)) { security_warning(0); exit(0); }
if (qpkg_check(package: "media-video/helixplayer", unaffected: make_list(), vulnerable: make_list("lt 1.0.6")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
