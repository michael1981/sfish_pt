
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14047);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:064: kon2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:064 (kon2).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in kon2, a Kanji emulator for the
console. A buffer overflow in the command line parsing can be
exploited, leading to local users being able to gain root privileges.
These updated packages provide a fix for this vulnerability.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:064");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1155");
script_summary(english: "Check for the version of the kon2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kon2-0.3.9b-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kon2-0.3.9b-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kon2-0.3.9b-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kon2-", release:"MDK8.2")
 || rpm_exists(rpm:"kon2-", release:"MDK9.0")
 || rpm_exists(rpm:"kon2-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2002-1155", value:TRUE);
}
exit(0, "Host is not affected");
