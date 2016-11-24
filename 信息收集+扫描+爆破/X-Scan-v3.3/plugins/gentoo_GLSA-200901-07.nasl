# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200901-07.xml
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
 script_id(35355);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200901-07");
 script_cve_id("CVE-2008-3162", "CVE-2008-3827", "CVE-2008-5616");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200901-07 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200901-07
(MPlayer: Multiple vulnerabilities)


    Multiple vulnerabilities have been reported in MPlayer:
    A
    stack-based buffer overflow was found in the str_read_packet() function
    in libavformat/psxstr.c when processing crafted STR files that
    interleave audio and video sectors (CVE-2008-3162).
    Felipe
    Andres Manzano reported multiple integer underflows in the
    demux_real_fill_buffer() function in demux_real.c when processing
    crafted Real Media files that cause the stream_read() function to read
    or write arbitrary memory (CVE-2008-3827).
    Tobias Klein
    reported a stack-based buffer overflow in the demux_open_vqf() function
    in libmpdemux/demux_vqf.c when processing malformed TwinVQ files
    (CVE-2008-5616).
  
Impact

    A remote attacker could entice a user to open a specially crafted STR,
    Real Media, or TwinVQ file to execute arbitrary code or cause a Denial of
    Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All MPlayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mplayer-1.0_rc2_p28058-r1 "
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3162');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3827');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-5616');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200901-07.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200901-07] MPlayer: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'MPlayer: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_rc2_p28058-r1 "), vulnerable: make_list("lt 1.0_rc2_p28058-r1 ")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
