
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25265);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:105: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:105 (fetchmail).");
 script_set_attribute(attribute: "description", value: "The APOP functionality in fetchmail's POP3 client implementation was
validating the APOP challenge too lightly, accepting random garbage
as a POP3 server's APOP challenge, rather than insisting it conform
to RFC-822 specifications.
As a result of this flaw, it made man-in-the-middle attacks easier than
necessary to retrieve the first few characters of the APOP secret,
allowing them to potentially brute force the remaining characters
easier than should be possible.
Updated packages have been patched to prevent these issues, however it
should be noted that the APOP MD5-based authentication scheme should
no longer be considered secure.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:105");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1558");
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

if ( rpm_check( reference:"fetchmail-6.3.4-3.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.3.4-3.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.3.4-3.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.3.6-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.3.6-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.3.6-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK2007.0")
 || rpm_exists(rpm:"fetchmail-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-1558", value:TRUE);
}
exit(0, "Host is not affected");
