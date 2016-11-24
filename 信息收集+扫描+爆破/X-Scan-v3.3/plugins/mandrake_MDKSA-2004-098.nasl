
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14754);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2004:098: libxpm4");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:098 (libxpm4).");
 script_set_attribute(attribute: "description", value: "Chris Evans found several stack and integer overflows in the libXpm code
of X.Org/XFree86 (from which the libxpm code is derived):
Stack overflows (CVE-2004-0687):
Careless use of strcat() in both the XPMv1 and XPMv2/3 xpmParseColors code
leads to a stack based overflow (parse.c).
Stack overflow reading pixel values in ParseAndPutPixels (create.c) as
well as ParsePixels (parse.c).
Integer Overflows (CVE-2004-0688):
Integer overflow allocating colorTable in xpmParseColors (parse.c) -
probably a crashable but not exploitable offence.
The updated packages have patches from Chris Evans and Matthieu Herrb
to address these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:098");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0687", "CVE-2004-0688");
script_summary(english: "Check for the version of the libxpm4 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libxpm4-3.4k-27.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-27.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libxpm4-", release:"MDK10.0")
 || rpm_exists(rpm:"libxpm4-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0687", value:TRUE);
 set_kb_item(name:"CVE-2004-0688", value:TRUE);
}
exit(0, "Host is not affected");
