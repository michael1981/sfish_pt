
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13992);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:007: dhcp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:007 (dhcp).");
 script_set_attribute(attribute: "description", value: "Several potential vulnerabilities were detected by the ISC (Internet
Software Consortium) in their dhcp server software. The
vulnerabilities affect the minires library and may be exploitable as stack
buffer overflows, which could lead to remote code execution. All Mandrake
Linux users are encouraged to upgrade; only Mandrake Linux 8.0 came with
dhcp 2.x and is not vulnerable.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:007");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0026");
script_summary(english: "Check for the version of the dhcp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dhcp-3.0b2pl9-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0b2pl9-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0b2pl9-4.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-0.rc12.2.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1rc8.2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1rc9.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"dhcp-", release:"MDK7.2")
 || rpm_exists(rpm:"dhcp-", release:"MDK8.1")
 || rpm_exists(rpm:"dhcp-", release:"MDK8.2")
 || rpm_exists(rpm:"dhcp-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0026", value:TRUE);
}
exit(0, "Host is not affected");
