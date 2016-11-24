
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14160);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2004:061: dhcp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:061 (dhcp).");
 script_set_attribute(attribute: "description", value: "A vulnerability in how ISC's DHCPD handles syslog messages can allow a
malicious attacker with the ability to send special packets to the
DHCPD listening port to crash the daemon, causing a Denial of Service.
It is also possible that they may be able to execute arbitrary code on
the vulnerable server with the permissions of the user running DHCPD,
which is usually root.
A similar vulnerability also exists in the way ISC's DHCPD makes use
of the vsnprintf() function on system that do not support vsnprintf().
This vulnerability could also be used to execute arbitrary code and/or
perform a DoS attack. The vsnprintf() statements that have this
problem are defined after the vulnerable code noted above, which would
trigger the previous problem rather than this one.
Thanks to Gregory Duchemin and Solar Designer for discovering these
flaws.
The updated packages contain 3.0.1rc14 which is not vulnerable to these
problems. Only ISC DHCPD 3.0.1rc12 and 3.0.1rc13 are vulnerable to
these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:061");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0460", "CVE-2004-0461");
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

if ( rpm_check( reference:"dhcp-client-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1.rc14.0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-client-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-common-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-devel-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-relay-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dhcp-server-3.0-1.rc14.0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"dhcp-", release:"MDK10.0")
 || rpm_exists(rpm:"dhcp-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0460", value:TRUE);
 set_kb_item(name:"CVE-2004-0461", value:TRUE);
}
exit(0, "Host is not affected");
