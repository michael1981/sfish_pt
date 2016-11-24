# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200409-12.xml
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
 script_id(14677);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200409-12");
 script_cve_id("CVE-2004-0817", "CVE-2004-0802");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200409-12 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200409-12
(ImageMagick, imlib, imlib2: BMP decoding buffer overflows)


    Due to improper bounds checking, ImageMagick and imlib are vulnerable to a
    buffer overflow when decoding runlength-encoded bitmaps. This bug can be
    exploited using a specially-crafted BMP image and could potentially allow
    remote code execution when this image is decoded by the user.
  
Impact

    A specially-crafted runlength-encoded BMP could lead ImageMagick and imlib
    to crash or potentially execute arbitrary code.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ImageMagick users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-gfx/imagemagick-6.0.7.1"
    # emerge ">=media-gfx/imagemagick-6.0.7.1"
    All imlib users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/imlib-1.9.14-r2"
    # emerge ">=media-libs/imlib-1.9.14-r2"
    All imlib2 users should upgrade to the latest version:
    # emerge sync
    # emerge -pv ">=media-libs/imlib2-1.1.2"
    # emerge ">=media-libs/imlib2-1.1.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0817');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0802');
script_set_attribute(attribute: 'see_also', value: 'http://studio.imagemagick.org/pipermail/magick-developers/2004-August/002011.html');
script_set_attribute(attribute: 'see_also', value: 'http://securitytracker.com/alerts/2004/Aug/1011104.html');
script_set_attribute(attribute: 'see_also', value: 'http://securitytracker.com/alerts/2004/Aug/1011105.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200409-12.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200409-12] ImageMagick, imlib, imlib2: BMP decoding buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick, imlib, imlib2: BMP decoding buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-libs/imlib", unaffected: make_list("ge 1.9.14-r2"), vulnerable: make_list("lt 1.9.14-r2")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.0.7.1"), vulnerable: make_list("lt 6.0.7.1")
)) { security_hole(0); exit(0); }
if (qpkg_check(package: "media-libs/imlib2", unaffected: make_list("ge 1.1.2"), vulnerable: make_list("lt 1.1.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
