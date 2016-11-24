# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200709-05.xml
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
 script_id(26095);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200709-05");
 script_cve_id("CVE-2007-3410");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200709-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200709-05
(RealPlayer: Buffer overflow)


    A stack-based buffer overflow vulnerability has been reported in the
    SmilTimeValue::parseWallClockValue() function in smlprstime.cpp when
    handling HH:mm:ss.f type time formats.
  
Impact

    By enticing a user to open a specially crafted SMIL (Synchronized
    Multimedia Integration Language) file, an attacker could be able to
    execute arbitrary code with the privileges of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All RealPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/realplayer-10.0.9"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3410');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200709-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200709-05] RealPlayer: Buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'RealPlayer: Buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/realplayer", unaffected: make_list("ge 10.0.9"), vulnerable: make_list("lt 10.0.9")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
