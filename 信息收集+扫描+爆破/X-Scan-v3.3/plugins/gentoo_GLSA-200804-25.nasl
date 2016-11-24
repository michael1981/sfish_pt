# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200804-25.xml
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
 script_id(32045);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200804-25");
 script_cve_id("CVE-2007-6681", "CVE-2008-0073", "CVE-2008-1489", "CVE-2008-1768", "CVE-2008-1769", "CVE-2008-1881");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200804-25 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200804-25
(VLC: User-assisted execution of arbitrary code)


    Multiple vulnerabilities were found in VLC:
    Luigi Auriemma discovered that the stack-based buffer overflow when
    reading subtitles, which has been reported as CVE-2007-6681 in GLSA
    200803-13, was not properly fixed (CVE-2008-1881).
    Alin Rad Pop of Secunia reported an array indexing vulnerability in the
    sdpplin_parse() function when processing streams from RTSP servers in
    Xine code, which is also used in VLC (CVE-2008-0073).
    Drew Yao and Nico Golde reported an integer overflow in the
    MP4_ReadBox_rdrf() function in the file libmp4.c leading to a
    heap-based buffer overflow when reading MP4 files (CVE-2008-1489).
    Drew Yao also reported integer overflows in the MP4 demuxer,
    the Real demuxer and in the Cinepak codec, which might lead to buffer
    overflows (CVE-2008-1768).
    Drew Yao finally discovered and a
    boundary error in Cinepak, which might lead to memory corruption
    (CVE-2008-1769).
  
Impact

    A remote attacker could entice a user to open a specially crafted media
    file or stream, possibly resulting in the remote execution of arbitrary
    code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All VLC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/vlc-0.8.6f"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6681');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0073');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1489');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1768');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1769');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-1881');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-13.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200804-25.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200804-25] VLC: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VLC: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/vlc", unaffected: make_list("ge 0.8.6f"), vulnerable: make_list("lt 0.8.6f")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
