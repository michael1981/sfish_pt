
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38204);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:101: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:101 (xpdf).");
 script_set_attribute(attribute: "description", value: "Multiple buffer overflows in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0146).
Multiple integer overflows in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0147).
An integer overflow in the JBIG2 decoder has unspecified
impact. (CVE-2009-0165).
A free of uninitialized memory flaw in the the JBIG2 decoder allows
remote to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0166).
Multiple input validation flaws in the JBIG2 decoder allows
remote attackers to execute arbitrary code via a crafted PDF file
(CVE-2009-0800).
An out-of-bounds read flaw in the JBIG2 decoder allows remote
attackers to cause a denial of service (crash) via a crafted PDF file
(CVE-2009-0799).
An integer overflow in the JBIG2 decoder allows remote attackers to
execute arbitrary code via a crafted PDF file (CVE-2009-1179).
A free of invalid data flaw in the JBIG2 decoder allows remote
attackers to execute arbitrary code via a crafted PDF (CVE-2009-1180).
A NULL pointer dereference flaw in the JBIG2 decoder allows remote
attackers to cause denial of service (crash) via a crafted PDF file
(CVE-2009-1181).
Multiple buffer overflows in the JBIG2 MMR decoder allows remote
attackers to cause denial of service or to execute arbitrary code
via a crafted PDF file (CVE-2009-1182, CVE-2009-1183).
This update provides fixes for that vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:101");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
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

if ( rpm_check( reference:"xpdf-3.02-8.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-common-3.02-8.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-tools-3.02-8.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.02-10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-common-3.02-10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-3.02-12.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpdf-common-3.02-12.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xpdf-", release:"MDK2008.0")
 || rpm_exists(rpm:"xpdf-", release:"MDK2008.1")
 || rpm_exists(rpm:"xpdf-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-0146", value:TRUE);
 set_kb_item(name:"CVE-2009-0147", value:TRUE);
 set_kb_item(name:"CVE-2009-0165", value:TRUE);
 set_kb_item(name:"CVE-2009-0166", value:TRUE);
 set_kb_item(name:"CVE-2009-0799", value:TRUE);
 set_kb_item(name:"CVE-2009-0800", value:TRUE);
 set_kb_item(name:"CVE-2009-1179", value:TRUE);
 set_kb_item(name:"CVE-2009-1180", value:TRUE);
 set_kb_item(name:"CVE-2009-1181", value:TRUE);
 set_kb_item(name:"CVE-2009-1182", value:TRUE);
 set_kb_item(name:"CVE-2009-1183", value:TRUE);
}
exit(0, "Host is not affected");
