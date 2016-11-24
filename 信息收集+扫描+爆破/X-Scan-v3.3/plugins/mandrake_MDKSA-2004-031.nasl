
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14130);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:031-1: utempter");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:031-1 (utempter).");
 script_set_attribute(attribute: "description", value: "Steve Grubb discovered two potential issues in the utempter program:
1) If the path to the device contained /../ or /./ or //, the
program was not exiting as it should. It would be possible to use something
like /dev/../tmp/tty0, and then if /tmp/tty0 were deleted and symlinked
to another important file, programs that have root privileges that do no
further validation can then overwrite whatever the symlink pointed to.
2) Several calls to strncpy without a manual termination of the string.
This would most likely crash utempter.
The updated packages are patched to correct these problems.
Update:
The second portion of the patch to address the manual termination of
the string has been determined to be uneccessary, as well as reducing the
length of utmp strings by one character. As such, it has been removed.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:031-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0233");
script_summary(english: "Check for the version of the utempter package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libutempter0-0.5.2-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libutempter0-devel-0.5.2-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"utempter-0.5.2-12.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libutempter0-0.5.2-10.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libutempter0-devel-0.5.2-10.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"utempter-0.5.2-10.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libutempter0-0.5.2-12.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libutempter0-devel-0.5.2-12.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"utempter-0.5.2-12.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"utempter-", release:"MDK10.0")
 || rpm_exists(rpm:"utempter-", release:"MDK9.1")
 || rpm_exists(rpm:"utempter-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0233", value:TRUE);
}
exit(0, "Host is not affected");
