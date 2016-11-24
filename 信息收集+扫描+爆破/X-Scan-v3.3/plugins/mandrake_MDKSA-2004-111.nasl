
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24551);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2004:111: wxGTK2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:111 (wxGTK2).");
 script_set_attribute(attribute: "description", value: "Several vulnerabilities have been discovered in the libtiff package;
wxGTK2 uses a libtiff code tree, so it may have the same
vulnerabilities:
Chris Evans discovered several problems in the RLE (run length
encoding) decoders that could lead to arbitrary code execution.
(CVE-2004-0803)
Matthias Clasen discovered a division by zero through an integer
overflow. (CVE-2004-0804)
Dmitry V. Levin discovered several integer overflows that caused
malloc issues which can result to either plain crash or memory
corruption. (CVE-2004-0886)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:111");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");
script_summary(english: "Check for the version of the wxGTK2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libwxgtk2.5-2.5.0-0.cvs20030817.1.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwxgtk2.5-devel-2.5.0-0.cvs20030817.1.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwxgtkgl2.5-2.5.0-0.cvs20030817.1.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wxGTK2.5-2.5.0-0.cvs20030817.1.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"wxGTK2.5-2.5.1-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwxgtk2.5_1-2.5.1-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwxgtk2.5_1-devel-2.5.1-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libwxgtkgl2.5_1-2.5.1-5.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"wxGTK2-", release:"MDK10.0")
 || rpm_exists(rpm:"wxGTK2-", release:"MDK10.1") )
{
 set_kb_item(name:"CVE-2004-0803", value:TRUE);
 set_kb_item(name:"CVE-2004-0804", value:TRUE);
 set_kb_item(name:"CVE-2004-0886", value:TRUE);
}
exit(0, "Host is not affected");
