
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40585);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:201: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:201 (fetchmail).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been found and corrected in fetchmail:
socket.c in fetchmail before 6.3.11 does not properly handle a ' '
character in a domain name in the subject's Common Name (CN) field
of an X.509 certificate, which allows man-in-the-middle attackers
to spoof arbitrary SSL servers via a crafted certificate issued by a
legitimate Certification Authority, a related issue to CVE-2009-2408
(CVE-2009-2666).
This update provides a solution to this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:201");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-2408", "CVE-2009-2666");
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

if ( rpm_check( reference:"fetchmail-6.3.8-7.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.3.8-7.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.3.8-7.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.3.8-8.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.3.8-8.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.3.8-8.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.3.9-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-6.3.9-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-daemon-6.3.9-1.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"fetchmail-", release:"MDK2008.1")
 || rpm_exists(rpm:"fetchmail-", release:"MDK2009.0")
 || rpm_exists(rpm:"fetchmail-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-2408", value:TRUE);
 set_kb_item(name:"CVE-2009-2666", value:TRUE);
}
exit(0, "Host is not affected");
