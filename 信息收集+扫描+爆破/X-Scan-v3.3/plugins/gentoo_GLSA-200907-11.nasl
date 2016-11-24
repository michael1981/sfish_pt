# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200907-11.xml
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
 script_id(39782);
 script_version("$Revision: 1.2 $");
 script_xref(name: "GLSA", value: "200907-11");
 script_cve_id("CVE-2009-0386", "CVE-2009-0387", "CVE-2009-0397", "CVE-2009-0586", "CVE-2009-1932");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200907-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200907-11
(GStreamer plug-ins: User-assisted execution of arbitrary code)


    Multiple vulnerabilities have been reported in several GStreamer
    plug-ins:
    Tobias Klein reported two heap-based buffer overflows and an array
    index error in the qtdemux_parse_samples() function in gst-plugins-good
    when processing a QuickTime media .mov file (CVE-2009-0386,
    CVE-2009-0387, CVE-2009-0397).
    Thomas Hoger of the Red Hat Security Response Team reported an integer
    overflow that can lead to a heap-based buffer overflow in the
    gst_vorbis_tag_add_coverart() function in gst-plugins-base when
    processing COVERART tags (CVE-2009-0586).
    Tielei Wang of ICST-ERCIS, Peking University reported multiple integer
    overflows leading to buffer overflows in gst-plugins-libpng when
    processing a PNG file (CVE-2009-1932).
  
Impact

    A remote attacker could entice a user or automated system using a
    GStreamer plug-in to process a specially crafted file, resulting in the
    execution of arbitrary code or a Denial of Service.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All gst-plugins-good users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/gst-plugins-good-0.10.14"
    All gst-plugins-base users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-libs/gst-plugins-base-0.10.22"
    All gst-plugins-libpng users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-plugins/gst-plugins-libpng-0.10.14-r1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0386');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0387');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0397');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0586');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-1932');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200907-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200907-11] GStreamer plug-ins: User-assisted execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'GStreamer plug-ins: User-assisted execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/gst-plugins-good", unaffected: make_list("ge 0.10.14"), vulnerable: make_list("lt 0.10.14")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-plugins/gst-plugins-libpng", unaffected: make_list("ge 0.10.14-r1"), vulnerable: make_list("lt 0.10.14-r1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-libs/gst-plugins-base", unaffected: make_list("ge 0.10.22"), vulnerable: make_list("lt 0.10.22")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
