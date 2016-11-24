
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29299);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDKSA-2007:242: e2fsprogs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:242 (e2fsprogs).");
 script_set_attribute(attribute: "description", value: "Rafal Wojtczuk of McAfee AVERT Research found that e2fsprogs contained
multiple integer overflows in memory allocations, based on sizes
taken directly from filesystem information. These flaws could result
in heap-based overflows potentially allowing for the execution of
arbitrary code.
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:242");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-5497");
script_summary(english: "Check for the version of the e2fsprogs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"e2fsprogs-1.39-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libext2fs2-1.39-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libext2fs2-devel-1.39-2.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-1.39-5.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libext2fs2-1.39-5.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libext2fs2-devel-1.39-5.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"e2fsprogs-1.40.2-5.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libext2fs-devel-1.40.2-5.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libext2fs2-1.40.2-5.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"e2fsprogs-", release:"MDK2007.0")
 || rpm_exists(rpm:"e2fsprogs-", release:"MDK2007.1")
 || rpm_exists(rpm:"e2fsprogs-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-5497", value:TRUE);
}
exit(0, "Host is not affected");
