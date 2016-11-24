# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200705-13.xml
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
 script_id(25209);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200705-13");
 script_cve_id("CVE-2007-1797");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200705-13 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200705-13
(ImageMagick: Multiple buffer overflows)


    iDefense Labs has discovered multiple integer overflows in ImageMagick
    in the functions ReadDCMImage() and ReadXWDImage(), that are used to
    process DCM and XWD files.
  
Impact

    An attacker could entice a user to open specially crafted XWD or DCM
    file, resulting in heap-based buffer overflows and possibly the
    execution of arbitrary code with the privileges of the user running
    ImageMagick. Note that this user may be httpd or any other account used
    by applications relying on the ImageMagick tools to automatically
    process images.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.3.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-1797');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200705-13.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200705-13] ImageMagick: Multiple buffer overflows');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick: Multiple buffer overflows');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.3.3"), vulnerable: make_list("lt 6.3.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
