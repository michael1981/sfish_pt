
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15548);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:113: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:113 (xpdf).");
 script_set_attribute(attribute: "description", value: "Chris Evans discovered numerous vulnerabilities in the xpdf package:
Multiple integer overflow issues affecting xpdf-2.0 and xpdf-3.0.
Also programs like cups which have embedded versions of xpdf.
These can result in writing an arbitrary byte to an attacker controlled
location which probably could lead to arbitrary code execution.
(CVE-2004-0888)
Multiple integer overflow issues affecting xpdf-3.0 only.
These can result in DoS or possibly arbitrary code execution.
(CVE-2004-0889)
Chris also discovered issues with infinite loop logic error affecting
xpdf-3.0 only.
The updated packages are patched to deal with these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:113");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0888", "CVE-2004-0889");
script_summary(english: "Check for the version of the xpdf package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xpdf-3.00-5.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.00-7.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK10.0")
 || rpm_exists(rpm:"xpdf-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0888", value:TRUE);
 set_kb_item(name:"CVE-2004-0889", value:TRUE);
}
exit(0, "Host is not affected");
