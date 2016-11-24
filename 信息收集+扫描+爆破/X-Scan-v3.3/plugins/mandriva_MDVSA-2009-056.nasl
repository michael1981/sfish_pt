
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36601);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:056: net-snmp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:056 (net-snmp).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been identified and corrected in net-snmp:
The netsnmp_udp_fmtaddr function (snmplib/snmpUDPDomain.c) in
net-snmp 5.0.9 through 5.4.2, when using TCP wrappers for client
authorization, does not properly parse hosts.allow rules, which
allows remote attackers to bypass intended access restrictions
and execute SNMP queries, related to source/destination IP address
confusion. (CVE-2008-6123)
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:056");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-6123");
script_summary(english: "Check for the version of the net-snmp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libnet-snmp15-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp-devel-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libnet-snmp-static-devel-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-mibs-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-tkmib-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-trapd-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"net-snmp-utils-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-NetSNMP-5.4.2-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"net-snmp-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-6123", value:TRUE);
}
exit(0, "Host is not affected");
