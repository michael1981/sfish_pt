
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24646);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:033: wireshark");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:033 (wireshark).");
 script_set_attribute(attribute: "description", value: "Vulnerabilities in the LLT, IEEE 802.11, HTTP, and TCP dissectors were
discovered in versions of wireshark less than 0.99.5, as well as
various other bugs.
This updated provides wireshark 0.99.5 which is not vulnerable to these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:033");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-0456", "CVE-2007-0457", "CVE-2007-0458", "CVE-2007-0459");
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

if ( rpm_check( reference:"libwireshark0-0.99.5-0.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tshark-0.99.5-0.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-0.99.5-0.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wireshark-tools-0.99.5-0.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"wireshark-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2007-0456", value:TRUE);
 set_kb_item(name:"CVE-2007-0457", value:TRUE);
 set_kb_item(name:"CVE-2007-0458", value:TRUE);
 set_kb_item(name:"CVE-2007-0459", value:TRUE);
}
exit(0, "Host is not affected");
