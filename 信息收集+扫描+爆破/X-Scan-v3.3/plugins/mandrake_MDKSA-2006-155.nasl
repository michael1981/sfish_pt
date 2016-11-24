
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23899);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:155: ImageMagick");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:155 (ImageMagick).");
 script_set_attribute(attribute: "description", value: "Multiple buffer overflows in ImageMagick before 6.2.9 allow user-assisted
attackers to execute arbitrary code via crafted XCF images. (CVE-2006-3743)
Multiple integer overflows in ImageMagick before 6.2.9 allows user-assisted
attackers to execute arbitrary code via crafted Sun bitmap images that trigger
heap-based buffer overflows. (CVE-2006-3744)
Integer overflow in the ReadSGIImage function in sgi.c in ImageMagick before
6.2.9 allows user-assisted attackers to cause a denial of service (crash)
and possibly execute arbitrary code via large (1) bytes_per_pixel, (2)
columns, and (3) rows values, which trigger a heap-based buffer overflow.
(CVE-2006-4144)
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:155");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-3743", "CVE-2006-3744", "CVE-2006-4144");
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

if ( rpm_check( reference:"ImageMagick-6.2.4.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-doc-6.2.4.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick8.4.2-6.2.4.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libMagick8.4.2-devel-6.2.4.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Image-Magick-6.2.4.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ImageMagick-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-3743", value:TRUE);
 set_kb_item(name:"CVE-2006-3744", value:TRUE);
 set_kb_item(name:"CVE-2006-4144", value:TRUE);
}
exit(0, "Host is not affected");
