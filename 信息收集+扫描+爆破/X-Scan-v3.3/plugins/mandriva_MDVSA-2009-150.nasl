
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39849);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:150: libtiff");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:150 (libtiff).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in libtiff:
Buffer underflow in the LZWDecodeCompat function in libtiff 3.8.2
allows context-dependent attackers to cause a denial of service (crash)
via a crafted TIFF image, a different vulnerability than CVE-2008-2327
(CVE-2009-2285).
Fix several places in tiff2rgba and rgb2ycbcr that were being careless
about possible integer overflow in calculation of buffer sizes
(CVE-2009-2347).
This update provides fixes for these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:150");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2327", "CVE-2009-2285", "CVE-2009-2347");
script_summary(english: "Check for the version of the libtiff package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libtiff3-3.8.2-10.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.8.2-10.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.8.2-10.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.8.2-10.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.8.2-12.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.8.2-12.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.8.2-12.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.8.2-12.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.8.2-13.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.8.2-13.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.8.2-13.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.8.2-13.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"MDK2008.1")
 || rpm_exists(rpm:"libtiff-", release:"MDK2009.0")
 || rpm_exists(rpm:"libtiff-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2008-2327", value:TRUE);
 set_kb_item(name:"CVE-2009-2285", value:TRUE);
 set_kb_item(name:"CVE-2009-2347", value:TRUE);
}
exit(0, "Host is not affected");
