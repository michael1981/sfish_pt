
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13943);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2002:038-1: bind");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:038-1 (bind).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in the BIND9 DNS server in versions
prior to 9.2.1. An error condition will trigger the shutdown of the
server when the rdataset parameter to the dns_message_findtype()
function in message.c is not NULL as expected. This condition causes
the server to assert an error message and shutdown the BIND server.
The error condition can be remotely exploited by a special DNS packet.
This can only be used to create a Denial of Service on the server; the
error condition is correctly detected, so it will not allow an attacker
to execute arbitrary code on the server.
Update:
Sascha Kettler noticed that the version of BIND9 supplied originally
was in fact 9.2.1RC1 and mis-labelled as 9.2.1. The packages provided
in this update are BIND 9.2.1 final. Likewise, the buffer overflow
in the DNS resolver libraries, as noted in MDKSA-2002:043, has also
been fixed. Thanks to Bernhard Rosenkraenzer at Red Hat for
backporting the patches from 8.3.3 to 9.2.1.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:038-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0400", "CVE-2002-0651");
script_summary(english: "Check for the version of the bind package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"bind-9.2.1-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.1-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.1-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"caching-nameserver-8.1-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-9.2.1-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.1-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.1-2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"caching-nameserver-8.1-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-9.2.1-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.1-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.1-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"caching-nameserver-8.1-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"bind-", release:"MDK8.0")
 || rpm_exists(rpm:"bind-", release:"MDK8.1")
 || rpm_exists(rpm:"bind-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0400", value:TRUE);
 set_kb_item(name:"CVE-2002-0651", value:TRUE);
}
exit(0, "Host is not affected");
