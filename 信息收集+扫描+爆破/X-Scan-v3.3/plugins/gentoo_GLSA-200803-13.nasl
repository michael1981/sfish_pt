# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-13.xml
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
 script_id(31439);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200803-13");
 script_cve_id("CVE-2007-6681", "CVE-2007-6682", "CVE-2007-6683", "CVE-2007-6684", "CVE-2008-0295", "CVE-2008-0296", "CVE-2008-0984");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-13
(VLC: Multiple vulnerabilities)


    Multiple vulnerabilities were found in VLC:
    Michal Luczaj
    and Luigi Auriemma reported that VLC contains boundary errors when
    handling subtitles in the ParseMicroDvd(), ParseSSA(), and
    ParseVplayer() functions in the modules/demux/subtitle.c file, allowing
    for a stack-based buffer overflow (CVE-2007-6681).
    The web
    interface listening on port 8080/tcp contains a format string error in
    the httpd_FileCallBack() function in the network/httpd.c file
    (CVE-2007-6682).
    The browser plugin possibly contains an
    argument injection vulnerability (CVE-2007-6683).
    The RSTP
    module triggers a NULL pointer dereference when processing a request
    without a "Transport" parameter (CVE-2007-6684).
    Luigi
    Auriemma and Remi Denis-Courmont found a boundary error in the
    modules/access/rtsp/real_sdpplin.c file when processing SDP data for
    RTSP sessions (CVE-2008-0295) and a vulnerability in the
    libaccess_realrtsp plugin (CVE-2008-0296), possibly resulting in a
    heap-based buffer overflow.
    Felipe Manzano and Anibal Sacco
    (Core Security Technologies) discovered an arbitrary memory overwrite
    vulnerability in VLC\'s MPEG-4 file format parser (CVE-2008-0984).
  
Impact

    A remote attacker could send a long subtitle in a file that a user is
    enticed to open, a specially crafted MP4 input file, long SDP data, or
    a specially crafted HTTP request with a "Connection" header value
    containing format specifiers, possibly resulting in the remote
    execution of arbitrary code. Also, a Denial of Service could be caused
    and arbitrary files could be overwritten via the "demuxdump-file"
    option in a filename in a playlist or via an EXTVLCOPT statement in an
    MP3 file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All VLC users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/vlc-0.8.6e"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6681');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6682');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6683');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6684');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0295');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0296');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0984');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-13] VLC: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VLC: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/vlc", unaffected: make_list("ge 0.8.6e"), vulnerable: make_list("lt 0.8.6e")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
