
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20831);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:026: bzip2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:026 (bzip2).");
 script_set_attribute(attribute: "description", value: "A bug was found in the way that bzgrep processed file names. If a
user could be tricked into running bzgrep on a file with a special
file name, it would be possible to execute arbitrary code with the
privileges of the user running bzgrep.
As well, the bzip2 package provided with Mandriva Linux 2006 did not
the patch applied to correct CVE-2005-0953 which was previously fixed
by MDKSA-2005:091; those packages are now properly patched.
The updated packages have been patched to correct these problems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:026");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0758", "CVE-2005-0953");
script_summary(english: "Check for the version of the bzip2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bzip2-1.0.2-20.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.2-20.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.2-20.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.2-20.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.2-20.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.2-20.3.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bzip2-1.0.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-1.0.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libbzip2_1-devel-1.0.3-1.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"bzip2-", release:"MDK10.1")
 || rpm_exists(rpm:"bzip2-", release:"MDK10.2")
 || rpm_exists(rpm:"bzip2-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-0758", value:TRUE);
 set_kb_item(name:"CVE-2005-0953", value:TRUE);
}
exit(0, "Host is not affected");
