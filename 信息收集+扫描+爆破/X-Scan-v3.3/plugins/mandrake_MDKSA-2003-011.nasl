
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13996);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:011: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:011 (fetchmail).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in all versions of fetchmail prior to 6.2.0
that allows a remote attacker to crash fetchmail and potentially execute
arbitrary code by sending carefully crafted email wihch is then parsed by
fetchmail. The vulnerability has been fixed in these patched packages of
fetchmail.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:011");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1365");
script_summary(english: "Check for the version of the fetchmail package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.1.0-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.1.0-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.1.0-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK7.2")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.0")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.2")
 || rpm_exists(rpm:"fetchmail-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1365", value:TRUE);
}
exit(0, "Host is not affected");
