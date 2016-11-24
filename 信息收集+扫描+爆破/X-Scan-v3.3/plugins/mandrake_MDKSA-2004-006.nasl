
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14106);
 script_version ("$Revision: 1.9 $");
 script_name(english: "MDKSA-2004:006-1: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:006-1 (gaim).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities were discovered in the gaim instant
messenger program by Steffan Esser, versions 0.75 and earlier.
Thanks to Jacques A. Vidrine for providing initial patches.
Multiple buffer overflows exist in gaim 0.75 and earlier: When
parsing cookies in a Yahoo web connection; YMSG protocol overflows
parsing the Yahoo login webpage; a YMSG packet overflow; flaws in
the URL parser; and flaws in the HTTP Proxy connect (CAN-2004-006).
A buffer overflow in gaim 0.74 and earlier in the Extract Info Field
Function used for MSN and YMSG protocol handlers (CAN-2004-007).
An integer overflow in gaim 0.74 and earlier, when allocating memory
for a directIM packet results in a heap overflow (CVE-2004-0008).
Update:
The patch used to correct the problem was slightly malformed and
could cause an infinite loop and crash with the Yahoo protocol.
The new packages have a corrected patch that resolves the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:006-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
script_summary(english: "Check for the version of the gaim package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gaim-0.75-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-encrypt-0.75-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-0.75-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-0.75-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-encrypt-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-festival-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-0.75-1.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK9.1")
 || rpm_exists(rpm:"gaim-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0006", value:TRUE);
 set_kb_item(name:"CVE-2004-0007", value:TRUE);
 set_kb_item(name:"CVE-2004-0008", value:TRUE);
}
exit(0, "Host is not affected");
