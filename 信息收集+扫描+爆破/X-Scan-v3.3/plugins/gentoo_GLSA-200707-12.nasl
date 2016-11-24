# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200707-12.xml
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
 script_id(25808);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200707-12");
 script_cve_id("CVE-2007-3316");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200707-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200707-12
(VLC media player: Format string vulnerabilities)


    David Thiel from iSEC Partners Inc. discovered format string errors in
    various plugins when parsing data. The affected plugins include Vorbis,
    Theora, CDDA and SAP.
  
Impact

    A remote attacker could entice a user to open a specially crafted media
    file, possibly resulting in the execution of arbitrary code with the
    privileges of the user running VLC media player.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All VLC media player users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/vlc-0.8.6c"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-3316');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200707-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200707-12] VLC media player: Format string vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VLC media player: Format string vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/vlc", unaffected: make_list("ge 0.8.6c"), vulnerable: make_list("lt 0.8.6c")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
