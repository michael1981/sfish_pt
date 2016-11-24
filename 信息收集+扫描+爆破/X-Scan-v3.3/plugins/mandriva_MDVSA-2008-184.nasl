
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37814);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2008:184: libtiff");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:184 (libtiff).");
 script_set_attribute(attribute: "description", value: "Drew Yao of the Apple Product Security Team reported multiple uses of
uninitialized values in libtiff's LZW compression algorithm decoder.
An attacker could create a carefully crafted LZW-encoded TIFF file that
would cause an application linked to libtiff to crash or potentially
execute arbitrary code (CVE-2008-2327).
The updated packages have been patched to prevent this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:184");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2327");
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

if ( rpm_check( reference:"libtiff3-3.8.2-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.8.2-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.8.2-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.8.2-8.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.8.2-8.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.8.2-8.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.8.2-8.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.8.2-8.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-3.8.2-10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-devel-3.8.2-10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff3-static-devel-3.8.2-10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-progs-3.8.2-10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libtiff-", release:"MDK2007.1")
 || rpm_exists(rpm:"libtiff-", release:"MDK2008.0")
 || rpm_exists(rpm:"libtiff-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-2327", value:TRUE);
}
exit(0, "Host is not affected");
