
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14117);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2004:017: pwlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:017 (pwlib).");
 script_set_attribute(attribute: "description", value: "The NISCC uncovered bugs in pwlib prior to version 1.6.0 via a test
suite for the H.225 protocol. An attacker could trigger these bugs
by sending carefully crafted messages to an application that uses
pwlib, and the severity would vary based on the application, but
likely would result in a Denial of Service (DoS).
The updated packages provide backported fixes from Craig Southeren
of the OpenH323 project to protect against this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:017");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0097");
script_summary(english: "Check for the version of the pwlib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pwlib1-1.4.7-3.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pwlib1-devel-1.4.7-3.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpwlib1-1.5.0-15.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libpwlib1-devel-1.5.0-15.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pwlib-", release:"MDK9.1")
 || rpm_exists(rpm:"pwlib-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0097", value:TRUE);
}
exit(0, "Host is not affected");
