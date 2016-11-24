
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36583);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:001-1: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:001-1 (wireshark).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities in the Wireshark program were found that
could cause crashes, excessive looping, or arbitrary code execution.
This update provides Wireshark 0.99.7 which is not vulnerable to
these issues.
An updated version of libsmi is also being provided, not because
of security issues, but because this version of wireshark uses it
instead of net-snmp for SNMP support.
Update:
This update is being reissued without libcap (kernel capabilities)
support, as that is not required by the original released packages,
and thus gave trouble for a number of users.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:001-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-6111", "CVE-2007-6112", "CVE-2007-6113", "CVE-2007-6114", "CVE-2007-6115", "CVE-2007-6116", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6119", "CVE-2007-6120", "CVE-2007-6121", "CVE-2007-6438", "CVE-2007-6439", "CVE-2007-6441", "CVE-2007-6450", "CVE-2007-6451");
script_summary(english: "Check for the version of the wireshark package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libwireshark0-0.99.7-0.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tshark-0.99.7-0.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.7-0.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-tools-0.99.7-0.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwireshark0-0.99.7-0.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tshark-0.99.7-0.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.7-0.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-tools-0.99.7-0.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwireshark-devel-0.99.7-0.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwireshark0-0.99.7-0.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tshark-0.99.7-0.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.7-0.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-tools-0.99.7-0.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"wireshark-", release:"MDK2007.0")
 || rpm_exists(rpm:"wireshark-", release:"MDK2007.1")
 || rpm_exists(rpm:"wireshark-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-6111", value:TRUE);
 set_kb_item(name:"CVE-2007-6112", value:TRUE);
 set_kb_item(name:"CVE-2007-6113", value:TRUE);
 set_kb_item(name:"CVE-2007-6114", value:TRUE);
 set_kb_item(name:"CVE-2007-6115", value:TRUE);
 set_kb_item(name:"CVE-2007-6116", value:TRUE);
 set_kb_item(name:"CVE-2007-6117", value:TRUE);
 set_kb_item(name:"CVE-2007-6118", value:TRUE);
 set_kb_item(name:"CVE-2007-6119", value:TRUE);
 set_kb_item(name:"CVE-2007-6120", value:TRUE);
 set_kb_item(name:"CVE-2007-6121", value:TRUE);
 set_kb_item(name:"CVE-2007-6438", value:TRUE);
 set_kb_item(name:"CVE-2007-6439", value:TRUE);
 set_kb_item(name:"CVE-2007-6441", value:TRUE);
 set_kb_item(name:"CVE-2007-6450", value:TRUE);
 set_kb_item(name:"CVE-2007-6451", value:TRUE);
}
exit(0, "Host is not affected");
