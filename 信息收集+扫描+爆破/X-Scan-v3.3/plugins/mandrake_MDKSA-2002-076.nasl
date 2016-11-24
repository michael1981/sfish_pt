
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13975);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2002:076: perl-MailTools");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:076 (perl-MailTools).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in Mail::Mailer perl module by the SuSE
security team during an audit. The vulnerability allows remote
attackers to execute arbitrary commands in certain circumstances due
to the usage of mailx as the default mailer, a program that allows
commands to be embedded in the mail body.
This module is used by some auto-response programs and spam filters
which make use of Mail::Mailer.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:076");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1271");
script_summary(english: "Check for the version of the perl-MailTools package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-MailTools-1.47-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"perl-MailTools-", release:"MDK7.2")
 || rpm_exists(rpm:"perl-MailTools-", release:"MDK8.0")
 || rpm_exists(rpm:"perl-MailTools-", release:"MDK8.1")
 || rpm_exists(rpm:"perl-MailTools-", release:"MDK8.2")
 || rpm_exists(rpm:"perl-MailTools-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1271", value:TRUE);
}
exit(0, "Host is not affected");
