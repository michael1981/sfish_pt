
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13941);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2002:036: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:036 (fetchmail).");
 script_set_attribute(attribute: "description", value: "A problem was discovered with versions of fetchmail prior to 5.9.10
that was triggered by retreiving mail from an IMAP server. The
fetchmail client will allocate an array to store the sizes of the
messages it is attempting to retrieve. This array size is determined
by the number of messages the server is claiming to have, and fetchmail
would not check whether or not the number of messages the server was
claiming was too high. This would allow a malicious server to make the
fetchmail process write data outside of the array bounds.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:036");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0146");
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

if ( rpm_check( reference:"fetchmail-5.9.11-6.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.11-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.3mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.11-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.11-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-5.9.11-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-5.9.11-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.11-6.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK7.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK7.2")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.0")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0146", value:TRUE);
}
exit(0, "Host is not affected");
