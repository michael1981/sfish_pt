
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38865);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:121: lcms");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:121 (lcms).");
 script_set_attribute(attribute: "description", value: "Multiple security vulnerabilities has been identified and fixed in
Little cms:
A memory leak flaw allows remote attackers to cause a denial of service
(memory consumption and application crash) via a crafted image file
(CVE-2009-0581).
Multiple integer overflows allow remote attackers to execute arbitrary
code via a crafted image file that triggers a heap-based buffer
overflow (CVE-2009-0723).
Multiple stack-based buffer overflows allow remote attackers to
execute arbitrary code via a crafted image file associated with a large
integer value for the (1) input or (2) output channel (CVE-2009-0733).
A flaw in the transformations of monochrome profiles allows remote
attackers to cause denial of service triggered by a NULL pointer
dereference via a crafted image file (CVE-2009-0793).
This update provides fixes for these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:121");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793");
script_summary(english: "Check for the version of the lcms package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lcms-1.18-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"liblcms1-1.18-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"liblcms-devel-1.18-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-lcms-1.18-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lcms-1.18-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"liblcms1-1.18-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"liblcms-devel-1.18-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-lcms-1.18-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lcms-1.18-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"liblcms1-1.18-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"liblcms-devel-1.18-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"python-lcms-1.18-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"lcms-", release:"MDK2008.1")
 || rpm_exists(rpm:"lcms-", release:"MDK2009.0")
 || rpm_exists(rpm:"lcms-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-0581", value:TRUE);
 set_kb_item(name:"CVE-2009-0723", value:TRUE);
 set_kb_item(name:"CVE-2009-0733", value:TRUE);
 set_kb_item(name:"CVE-2009-0793", value:TRUE);
}
exit(0, "Host is not affected");
