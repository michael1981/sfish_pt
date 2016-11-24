
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37419);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:058: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:058 (wireshark).");
 script_set_attribute(attribute: "description", value: "Buffer overflow in wiretap/netscreen.c in Wireshark 0.99.7 through
1.0.5 allows user-assisted remote attackers to cause a denial
of service (application crash) via a malformed NetScreen snoop
file. (CVE-2009-0599)
Wireshark 0.99.6 through 1.0.5 allows user-assisted remote attackers to
cause a denial of service (application crash) via a crafted Tektronix
K12 text capture file, as demonstrated by a file with exactly one
frame. (CVE-2009-0600)
Format string vulnerability in Wireshark 0.99.8 through 1.0.5
on non-Windows platforms allows local users to cause a denial of
service (application crash) via format string specifiers in the HOME
environment variable. (CVE-2009-0601)
This update provides Wireshark 1.0.6, which is not vulnerable to
these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:058");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0599", "CVE-2009-0600", "CVE-2009-0601");
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

if ( rpm_check( reference:"dumpcap-1.0.6-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwireshark0-1.0.6-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwireshark-devel-1.0.6-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rawshark-1.0.6-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tshark-1.0.6-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-1.0.6-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-tools-1.0.6-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"dumpcap-1.0.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwireshark0-1.0.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwireshark-devel-1.0.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rawshark-1.0.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tshark-1.0.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-1.0.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-tools-1.0.6-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"wireshark-", release:"MDK2008.1")
 || rpm_exists(rpm:"wireshark-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-0599", value:TRUE);
 set_kb_item(name:"CVE-2009-0600", value:TRUE);
 set_kb_item(name:"CVE-2009-0601", value:TRUE);
}
exit(0, "Host is not affected");
