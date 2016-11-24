
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14152);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:053: xpcd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:053 (xpcd).");
 script_set_attribute(attribute: "description", value: "A vulnerability in xpcd-svga, part of xpcd, was discovered by Jaguar.
xpcd-svga uses svgalib to display graphics on the console and it
would copy user-supplied data of an arbitrary length into a fixed-size
buffer in the pcd_open function.
As well, Steve Kemp previously discovered a buffer overflow in
xpcd-svga that could be triggered by a long HOME environment variable,
which could be exploited by a local attacker to obtain root
privileges.
The updated packages resolve these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:053");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0649", "CVE-2004-0402");
script_summary(english: "Check for the version of the xpcd package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xpcd-2.08-20.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpcd-gimp-2.08-20.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpcd-2.08-20.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xpcd-gimp-2.08-20.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xpcd-", release:"MDK10.0")
 || rpm_exists(rpm:"xpcd-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0649", value:TRUE);
 set_kb_item(name:"CVE-2004-0402", value:TRUE);
}
exit(0, "Host is not affected");
