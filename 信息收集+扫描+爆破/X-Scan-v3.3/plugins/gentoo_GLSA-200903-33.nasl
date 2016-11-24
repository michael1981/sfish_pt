# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200903-33.xml
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
 script_id(35969);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200903-33");
 script_cve_id("CVE-2008-3162", "CVE-2008-4866", "CVE-2008-4867", "CVE-2008-4868", "CVE-2008-4869", "CVE-2009-0385");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200903-33 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200903-33
(FFmpeg: Multiple vulnerabilities)


    Multiple vulnerabilities were found in FFmpeg:
    astrange
    reported a stack-based buffer overflow in the str_read_packet() in
    libavformat/psxstr.c when processing .str files (CVE-2008-3162).
    Multiple buffer overflows in libavformat/utils.c
    (CVE-2008-4866).
    A buffer overflow in libavcodec/dca.c
    (CVE-2008-4867).
    An unspecified vulnerability in the
    avcodec_close() function in libavcodec/utils.c (CVE-2008-4868).
    Unspecified memory leaks (CVE-2008-4869).
    Tobias Klein
    repoerted a NULL pointer dereference due to an integer signedness error
    in the fourxm_read_header() function in libavformat/4xm.c
    (CVE-2009-0385).
  
Impact

    A remote attacker could entice a user to open a specially crafted media
    file, possibly leading to the execution of arbitrary code with the
    privileges of the user running the application, or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All FFmpeg users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/ffmpeg-0.4.9_p20090201"
    All gst-plugins-ffmpeg users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-plugins/gst-plugins-ffmpeg-0.10.5"
    All Mplayer users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-video/mplayer-1.0_rc2_p28450"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3162 ');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4866');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4867');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4868');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4869');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0385');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200903-33.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200903-33] FFmpeg: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'FFmpeg: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-video/ffmpeg", unaffected: make_list("ge 0.4.9_p20090201"), vulnerable: make_list("lt 0.4.9_p20090201")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-plugins/gst-plugins-ffmpeg", unaffected: make_list("ge 0.10.5"), vulnerable: make_list("lt 0.10.5")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-video/mplayer", unaffected: make_list("ge 1.0_rc2_p28450"), vulnerable: make_list("lt 1.0_rc2_p28450")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
