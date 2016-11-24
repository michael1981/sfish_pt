
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14017);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:033: zlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:033 (zlib).");
 script_set_attribute(attribute: "description", value: "Richard Kettlewell discovered a buffer overflow vulnerability in the
zlib library's gzprintf() function. This can be used by attackers
to cause a denial of service or possibly even the execution of
arbitrary code. Our thanks to the OpenPKG team for providing a patch
which adds the necessary configure script checks to always use the
secure vsnprintf(3) and snprintf(3) functions, and which additionally
adjusts the code to correctly take into account the return value of
vsnprintf(3) and snprintf(3).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:033");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0107");
script_summary(english: "Check for the version of the zlib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"zlib-1.1.3-11.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib-devel-1.1.3-11.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.3-16.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.3-16.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.3-16.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.3-16.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.3-19.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.3-19.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-1.1.4-5.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zlib1-devel-1.1.4-5.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"zlib-", release:"MDK7.2")
 || rpm_exists(rpm:"zlib-", release:"MDK8.0")
 || rpm_exists(rpm:"zlib-", release:"MDK8.1")
 || rpm_exists(rpm:"zlib-", release:"MDK8.2")
 || rpm_exists(rpm:"zlib-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0107", value:TRUE);
}
exit(0, "Host is not affected");
