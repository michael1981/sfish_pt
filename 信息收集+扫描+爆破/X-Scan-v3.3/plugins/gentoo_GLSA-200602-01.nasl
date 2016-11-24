# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200602-01.xml
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
 script_id(20864);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200602-01");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200602-01 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200602-01
(GStreamer FFmpeg plugin: Heap-based buffer overflow)


    The GStreamer FFmpeg plugin contains derived code from the FFmpeg
    library, which is vulnerable to a heap overflow in the
    "avcodec_default_get_buffer()" function discovered by Simon Kilvington
    (see GLSA 200601-06).
  
Impact

    A remote attacker could entice a user to run an application using
    the GStreamer FFmpeg plugin on a maliciously crafted PIX_FMT_PAL8
    format image file (like PNG images), possibly leading to the execution
    of arbitrary code with the permissions of the user running the
    application.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All GStreamer FFmpeg plugin users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-plugins/gst-plugins-ffmpeg-0.8.7-r1"
  ');
script_set_attribute(attribute: 'risk_factor', value: 'Medium');
script_set_attribute(attribute: 'see_also', value: 'http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4048');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-06.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200602-01.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200602-01] GStreamer FFmpeg plugin: Heap-based buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GStreamer FFmpeg plugin: Heap-based buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-plugins/gst-plugins-ffmpeg", unaffected: make_list("ge 0.8.7-r1"), vulnerable: make_list("lt 0.8.7-r1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
