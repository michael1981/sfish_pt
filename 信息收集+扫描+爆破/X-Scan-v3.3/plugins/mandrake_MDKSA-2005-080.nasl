
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18173);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:080: xpm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:080 (xpm).");
 script_set_attribute(attribute: "description", value: "The XPM library which is part of the XFree86/XOrg project is used
by several GUI applications to process XPM image files.
An integer overflow flaw was found in libXPM, which is used by some
applications for loading of XPM images. An attacker could create a
malicious XPM file that would execute arbitrary code via a negative
bitmap_unit value if opened by a victim using an application linked
to the vulnerable library.
Updated packages are patched to correct all these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:080");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0605");
script_summary(english: "Check for the version of the xpm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libxpm4-3.4k-27.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.4.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-28.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-28.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-30.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-30.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xpm-", release:"MDK10.0")
 || rpm_exists(rpm:"xpm-", release:"MDK10.1")
 || rpm_exists(rpm:"xpm-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0605", value:TRUE);
}
exit(0, "Host is not affected");
