# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200407-23.xml
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
 script_id(14556);
 script_version("$Revision: 1.6 $");
 script_xref(name: "GLSA", value: "200407-23");
 script_cve_id("CVE-2004-0557");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200407-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200407-23
(SoX: Multiple buffer overflows)


    Ulf Harnhammar discovered two buffer overflows in the sox and play
    commands when handling WAV files with specially crafted header fields.
  
Impact

    By enticing a user to play or convert a specially crafted WAV file an
    attacker could execute arbitrary code with the permissions of the user
    running SoX.
  
Workaround

    There is no known workaround at this time. All users are encouraged to
    upgrade to the latest available version of SoX.
  
');
script_set_attribute(attribute:'solution', value: '
    All SoX users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-sound/sox-12.17.4-r2"
    # emerge ">=media-sound/sox-12.17.4-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1141.html');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0557');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200407-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200407-23] SoX: Multiple buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'SoX: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-sound/sox", unaffected: make_list("ge 12.17.4-r2"), vulnerable: make_list("le 12.17.4-r1")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
