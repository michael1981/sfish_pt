
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14054);
 script_version ("$Revision: 1.9 $");
 script_name(english: "MDKSA-2003:071-1: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:071-1 (xpdf).");
 script_set_attribute(attribute: "description", value: "Martyn Gilmore discovered flaws in various PDF viewers, including xpdf.
An attacker could place malicious external hyperlinks in a document
that, if followed, could execute arbitary shell commands with the
privileges of the person viewing the PDF document.
Update:
New packages are available as the previous patches that had been
applied did not correct all possible ways of exploiting this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:071-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0434");
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

if ( rpm_check( reference:"xpdf-1.01-4.3mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-2.01-2.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK9.0")
 || rpm_exists(rpm:"xpdf-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0434", value:TRUE);
}
exit(0, "Host is not affected");
