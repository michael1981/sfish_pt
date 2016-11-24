
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21776);
 script_version ("$Revision: 1.4 $");
 script_name(english: "MDKSA-2006:114-1: libwmf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:114-1 (libwmf).");
 script_set_attribute(attribute: "description", value: "Multiple buffer overflows in the gd graphics library (libgd) 2.0.21 and
earlier may allow remote attackers to execute arbitrary code via malformed
image files that trigger the overflows due to improper calls to the gdMalloc
function. (CVE-2004-0941)
Integer overflows were reported in the GD Graphics Library (libgd)
2.0.28, and possibly other versions. These overflows allow remote
attackers to cause a denial of service and possibly execute arbitrary
code via PNG image files with large image rows values that lead to a
heap-based buffer overflow in the gdImageCreateFromPngCtx() function.
Libwmf contains an embedded copy of the GD library code. (CVE-2004-0990)
Update:
The previous update incorrectly attributed the advisory text to
CVE-2004-0941, while it should have been CVE-2004-0990. Additional
review of the code found fixes for CVE-2004-0941 were missing and have
also been included in this update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:114-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0941", "CVE-2004-0990");
script_summary(english: "Check for the version of the libwmf package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libwmf0.2_7-0.2.8.3-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwmf0.2_7-devel-0.2.8.3-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwmf-0.2.8.3-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwmf0.2_7-0.2.8.3-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwmf0.2_7-devel-0.2.8.3-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwmf-0.2.8.3-6.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libwmf-", release:"MDK10.2")
 || rpm_exists(rpm:"libwmf-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2004-0941", value:TRUE);
 set_kb_item(name:"CVE-2004-0990", value:TRUE);
}
exit(0, "Host is not affected");
