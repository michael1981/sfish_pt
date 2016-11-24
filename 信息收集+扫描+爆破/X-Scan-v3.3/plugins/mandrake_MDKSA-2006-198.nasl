
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24583);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:198-1: imlib2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:198-1 (imlib2).");
 script_set_attribute(attribute: "description", value: "M Joonas Pihlaja discovered several vulnerabilities in the Imlib2
graphics library.
The load() function of several of the Imlib2 image loaders does not
check the width and height of an image before allocating memory. As a
result, a carefully crafted image file can trigger a segfault when an
application using Imlib2 attempts to view the image. (CVE-2006-4806)
The tga loader fails to bounds check input data to make sure the input
data doesn't load outside the memory mapped region. (CVE-2006-4807)
The RLE decoding loops of the load() function in the tga loader does
not check that the count byte of an RLE packet doesn't cause a heap
overflow of the pixel buffer. (CVE-2006-4808)
The load() function of the pnm loader writes arbitrary length user data
into a fixed size stack allocated buffer buf[] without bounds checking.
(CVE-2006-4809) Updated packages have been patched to correct these
issues.
Update:
An error in the previous patchset may affect JPEG image handling for
certain valid images. This new update corrects this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:198-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4806", "CVE-2006-4807", "CVE-2006-4808", "CVE-2006-4809");
script_summary(english: "Check for the version of the imlib2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"imlib2-data-1.2.1-1.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.2.1-1.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-devel-1.2.1-1.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.2.1-1.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.2.1-1.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"imlib2-data-1.2.2-3.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-1.2.2-3.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-devel-1.2.2-3.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-filters-1.2.2-3.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libimlib2_1-loaders-1.2.2-3.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"imlib2-", release:"MDK2006.0")
 || rpm_exists(rpm:"imlib2-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-4806", value:TRUE);
 set_kb_item(name:"CVE-2006-4807", value:TRUE);
 set_kb_item(name:"CVE-2006-4808", value:TRUE);
 set_kb_item(name:"CVE-2006-4809", value:TRUE);
}
exit(0, "Host is not affected");
