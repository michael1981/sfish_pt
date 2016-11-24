
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14063);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:081: postfix");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:081 (postfix).");
 script_set_attribute(attribute: "description", value: "Two vulnerabilities were discovered in the postfix MTA by Michal
Zalewski. Versions prior to 1.1.12 would allow an attacker to bounce-
scan private networks or use the daemon as a DDoS (Distributed Denial
of Service) tool by forcing the daemon to connect to an arbitrary
service at an arbitrary IP address and receiving either a bounce
message or by timing. As well, versions prior to 1.1.12 have a bug
where a malformed envelope address can cause the queue manager to
lock up until an entry is removed from the queue and also lock up
the SMTP listener leading to a DoS.
Postfix version 1.1.13 corrects these issues. The provided packages
have been patched to fix the vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:081");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0468", "CVE-2003-0540");
script_summary(english: "Check for the version of the postfix package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"postfix-20010228-20.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"postfix-1.1.13-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"postfix-", release:"MDK8.2")
 || rpm_exists(rpm:"postfix-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0468", value:TRUE);
 set_kb_item(name:"CVE-2003-0540", value:TRUE);
}
exit(0, "Host is not affected");
