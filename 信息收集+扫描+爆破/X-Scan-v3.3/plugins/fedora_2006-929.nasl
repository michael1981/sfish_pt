
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-929
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24172);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 5 2006-929: ImageMagick");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-929 (ImageMagick)");
 script_set_attribute(attribute: "description", value: "ImageMagick(TM) is an image display and manipulation tool for the X
Window System. ImageMagick can read and write JPEG, TIFF, PNM, GIF,
and Photo CD image formats. It can resize, rotate, sharpen, color
reduce, or add special effects to an image, and when finished you can
either save the completed work in the original format or a different
one. ImageMagick also includes command line programs for creating
animated or transparent .gifs, creating composite images, creating
thumbnail images, and more.

ImageMagick is one of your choices if you need a program to manipulate
and dis play images. If you want to develop your own applications
which use ImageMagick code or APIs, you need to install
ImageMagick-devel as well.

Update Information:

ImageMagick(TM) is an image display and manipulation tool
for the X Window System that can read and write multiple
image formats.

Tavis Ormandy discovered several integer and buffer overflow
flaws in the way ImageMagick decodes XCF, SGI, and Sun
bitmap graphic files. An attacker could execute arbitrary
code on a victim's machine if they were able to trick the
victim into opening a specially crafted image file.
(CVE-2006-3743, CVE-2006-4144)

Users of ImageMagick should upgrade to these updated
packages, which contain backported patches and are not
vulnerable to these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-3743", "CVE-2006-4144");
script_summary(english: "Check for the version of the ImageMagick package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ImageMagick-6.2.5.4-4.2.1.fc5.4", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
