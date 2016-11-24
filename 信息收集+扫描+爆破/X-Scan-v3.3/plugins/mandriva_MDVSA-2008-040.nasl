
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36980);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:040: SDL_image");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:040 (SDL_image).");
 script_set_attribute(attribute: "description", value: "The LWZReadByte() and IMG_LoadLBM_RW() functions in SDL_image
contain a boundary error that could be triggered to cause a static
buffer overflow and a heap-based buffer overflow. If a user using
an application linked against the SDL_image library were to open a
carefully crafted GIF or IFF ILBM file, the application could crash
or possibly allow for the execution of arbitrary code.
The updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:040");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-6697", "CVE-2008-0544");
script_summary(english: "Check for the version of the SDL_image package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libSDL_image1.2-1.2.5-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libSDL_image1.2-devel-1.2.5-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libSDL_image1.2-test-1.2.5-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libSDL_image1.2-1.2.5-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libSDL_image1.2-devel-1.2.5-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libSDL_image1.2-test-1.2.5-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libSDL_image1.2-1.2.6-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libSDL_image1.2-devel-1.2.6-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libSDL_image1.2-test-1.2.6-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"SDL_image-", release:"MDK2007.0")
 || rpm_exists(rpm:"SDL_image-", release:"MDK2007.1")
 || rpm_exists(rpm:"SDL_image-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-6697", value:TRUE);
 set_kb_item(name:"CVE-2008-0544", value:TRUE);
}
exit(0, "Host is not affected");
