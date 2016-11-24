
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(17677);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:065: ImageMagick");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:065 (ImageMagick).");
 script_set_attribute(attribute: "description", value: "A format string vulnerability was discovered in ImageMagick, in the
way it handles filenames. An attacker could execute arbitrary code on
a victim's machine provided they could trick them into opening a file
with a special name (CVE-2005-0397).
As well, Andrei Nigmatulin discovered a heap-based buffer overflow in
ImageMagick's image handler. An attacker could create a special
PhotoShop Document (PSD) image file in such a way that it would cause
ImageMagick to execute arbitray code when processing the image
(CVE-2005-0005).
Other vulnerabilities were discovered in ImageMagick versions prior
to 6.0:
A bug in the way that ImageMagick handles TIFF tags was discovered.
It was possible that a TIFF image with an invalid tag could cause
ImageMagick to crash (CVE-2005-0759).
A bug in ImageMagick's TIFF decoder was discovered where a specially-
crafted TIFF image could cause ImageMagick to crash (CVE-2005-0760).
A bug in ImageMagick's PSD parsing was discovered where a specially-
crafted PSD file could cause ImageMagick to crash (CVE-2005-0761).
Finally, a heap overflow bug was discovered in ImageMagick's SGI
parser. If an attacker could trick a user into opening a specially-
crafted SGI image file, ImageMagick would execute arbitrary code
(CVE-2005-0762).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:065");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0005", "CVE-2005-0397", "CVE-2005-0759", "CVE-2005-0760", "CVE-2005-0761", "CVE-2005-0762");
script_summary(english: "Check for the version of the ImageMagick package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ImageMagick-5.5.7.15-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-doc-5.5.7.15-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick5.5.7-5.5.7.15-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick5.5.7-devel-5.5.7.15-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Magick-5.5.7.15-6.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-6.0.4.4-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-doc-6.0.4.4-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick6.4.0-6.0.4.4-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick6.4.0-devel-6.0.4.4-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Magick-6.0.4.4-5.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ImageMagick-", release:"MDK10.0")
 || rpm_exists(rpm:"ImageMagick-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2005-0005", value:TRUE);
 set_kb_item(name:"CVE-2005-0397", value:TRUE);
 set_kb_item(name:"CVE-2005-0759", value:TRUE);
 set_kb_item(name:"CVE-2005-0760", value:TRUE);
 set_kb_item(name:"CVE-2005-0761", value:TRUE);
 set_kb_item(name:"CVE-2005-0762", value:TRUE);
}
exit(0, "Host is not affected");
