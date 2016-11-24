
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19891);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:131: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:131 (ethereal).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in versions of Ethereal
prior to version 0.10.12, including:
The SMB dissector could overflow a buffer or exhaust memory
(CVE-2005-2365).
iDefense discovered that several dissectors are vulnerable to
format string overflows (CVE-2005-2367).
A number of other portential crash issues in various dissectors
have also been corrected.
This update provides Ethereal 0.10.12 which is not vulnerable to these
issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:131");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2360", "CVE-2005-2361", "CVE-2005-2362", "CVE-2005-2363", "CVE-2005-2364", "CVE-2005-2365", "CVE-2005-2366", "CVE-2005-2367");
script_summary(english: "Check for the version of the ethereal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ethereal-0.10.12-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.12-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.12-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.12-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.12-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-tools-0.10.12-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libethereal0-0.10.12-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tethereal-0.10.12-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK10.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2360", value:TRUE);
 set_kb_item(name:"CVE-2005-2361", value:TRUE);
 set_kb_item(name:"CVE-2005-2362", value:TRUE);
 set_kb_item(name:"CVE-2005-2363", value:TRUE);
 set_kb_item(name:"CVE-2005-2364", value:TRUE);
 set_kb_item(name:"CVE-2005-2365", value:TRUE);
 set_kb_item(name:"CVE-2005-2366", value:TRUE);
 set_kb_item(name:"CVE-2005-2367", value:TRUE);
}
exit(0, "Host is not affected");
