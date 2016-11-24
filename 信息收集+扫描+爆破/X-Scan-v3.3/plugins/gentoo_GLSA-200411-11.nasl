# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200411-11.xml
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
 script_id(15645);
 script_version("$Revision: 1.8 $");
 script_xref(name: "GLSA", value: "200411-11");
 script_cve_id("CVE-2004-0981");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200411-11 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200411-11
(ImageMagick: EXIF buffer overflow)


    ImageMagick fails to do proper bounds checking when handling image files
    with EXIF information.
  
Impact

    An attacker could use an image file with specially-crafted EXIF information
    to cause arbitrary code execution with the permissions of the user running
    ImageMagick.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All ImageMagick users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=media-gfx/imagemagick-6.1.3.2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0981');
script_set_attribute(attribute: 'see_also', value: 'http://www.imagemagick.org/www/Changelog.html');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/12995/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200411-11.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200411-11] ImageMagick: EXIF buffer overflow');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ImageMagick: EXIF buffer overflow');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "media-gfx/imagemagick", unaffected: make_list("ge 6.1.3.2"), vulnerable: make_list("lt 6.1.3.2")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
