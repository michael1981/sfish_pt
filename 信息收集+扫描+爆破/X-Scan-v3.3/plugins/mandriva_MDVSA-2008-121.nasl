
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37537);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:121: freetype2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:121 (freetype2).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities were discovered in FreeType's Printer
Font Binary (PFB) font-file format parser. If a user were to load a
carefully crafted font file with a program linked against FreeType, it
could cause the application to crash or potentially execute arbitrary
code (CVE-2008-1806, CVE-2008-1807, CVE-2008-1808).
The updated packages have been patched to prevent this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:121");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
script_summary(english: "Check for the version of the freetype2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libfreetype6-2.3.1-3.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-devel-2.3.1-3.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-static-devel-2.3.1-3.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-2.3.5-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-devel-2.3.5-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-static-devel-2.3.5-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-2.3.5-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-devel-2.3.5-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libfreetype6-static-devel-2.3.5-2.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"freetype2-", release:"MDK2007.1")
 || rpm_exists(rpm:"freetype2-", release:"MDK2008.0")
 || rpm_exists(rpm:"freetype2-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-1806", value:TRUE);
 set_kb_item(name:"CVE-2008-1807", value:TRUE);
 set_kb_item(name:"CVE-2008-1808", value:TRUE);
}
exit(0, "Host is not affected");
