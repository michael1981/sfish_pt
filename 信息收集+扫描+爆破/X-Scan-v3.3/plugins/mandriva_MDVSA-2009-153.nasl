
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39872);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:153: dhcp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:153 (dhcp).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been found and corrected in ISC DHCP:
Integer overflow in the ISC dhcpd 3.0.x before 3.0.7 and 3.1.x before
3.1.1; and the DHCP server in EMC VMware Workstation before 5.5.5 Build
56455 and 6.x before 6.0.1 Build 55017, Player before 1.0.5 Build 56455
and Player 2 before 2.0.1 Build 55017, ACE before 1.0.3 Build 54075 and
ACE 2 before 2.0.1 Build 55017, and Server before 1.0.4 Build 56528;
allows remote attackers to cause a denial of service (daemon crash)
or execute arbitrary code via a malformed DHCP packet with a large
dhcp-max-message-size that triggers a stack-based buffer overflow,
related to servers configured to send many DHCP options to clients
(CVE-2007-0062).
This update provides fixes for this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:153");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-0062");
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

if ( rpm_check( reference:"dhcp-client-3.0.7-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0.7-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0.7-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-doc-3.0.7-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0.7-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0.7-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"dhcp-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2007-0062", value:TRUE);
}
exit(0, "Host is not affected");
