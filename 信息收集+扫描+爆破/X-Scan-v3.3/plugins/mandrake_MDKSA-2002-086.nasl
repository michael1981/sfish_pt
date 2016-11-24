
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13984);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2002:086: wget");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:086 (wget).");
 script_set_attribute(attribute: "description", value: "A vulnerability in all versions of wget prior to and including 1.8.2
was discovered by Steven M. Christey. The bug permits a malicious
FTP server to create or overwriet files anywhere on the local file
system by sending filenames beginning with '/' or containing '/../'.
This can be used to make vulnerable FTP clients write files that can
later be used for attack against the client machine.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:086");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1344");
script_summary(english: "Check for the version of the wget package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wget-1.8.2-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"wget-", release:"MDK7.2")
 || rpm_exists(rpm:"wget-", release:"MDK8.0")
 || rpm_exists(rpm:"wget-", release:"MDK8.1")
 || rpm_exists(rpm:"wget-", release:"MDK8.2")
 || rpm_exists(rpm:"wget-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1344", value:TRUE);
}
exit(0, "Host is not affected");
