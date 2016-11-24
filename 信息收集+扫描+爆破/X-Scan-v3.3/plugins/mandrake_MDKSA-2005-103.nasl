
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18550);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:103: sudo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:103 (sudo).");
 script_set_attribute(attribute: "description", value: "A race condition was discovered in sudo by Charles Morris. This could
lead to the escalation of privileges if /etc/sudoers allowed a user to
execute selected programs that were then followed by another line
containing the pseudo-command 'ALL'. By creating symbolic links at a
certain time, that user could execute arbitrary commands.
The updated packages have been patched to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:103");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1993");
script_summary(english: "Check for the version of the sudo package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sudo-1.6.7-0.p5.2.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p1-1.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.8p1-2.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"sudo-", release:"MDK10.0")
 || rpm_exists(rpm:"sudo-", release:"MDK10.1")
 || rpm_exists(rpm:"sudo-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1993", value:TRUE);
}
exit(0, "Host is not affected");
