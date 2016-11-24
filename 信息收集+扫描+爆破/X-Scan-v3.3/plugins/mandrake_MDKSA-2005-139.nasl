
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19896);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:139: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:139 (gaim).");
 script_set_attribute(attribute: "description", value: "Yet more vulnerabilities have been discovered in the gaim IM client.
Invalid characters in a sent file can cause Gaim to crash on some
systems (CVE-2005-2102); a remote AIM or ICQ user can cause a buffer
overflow in Gaim by setting an away message containing many AIM
substitution strings (CVE-2005-2103); a memory alignment bug in the
library used by Gaim to access the Gadu-Gadu network can result in
a buffer overflow on non-x86 architecture systems (CVE-2005-2370).
These problems have been corrected in gaim 1.5.0 which is provided with
this update.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:139");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2102", "CVE-2005-2103", "CVE-2005-2370");
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

if ( rpm_check( reference:"gaim-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.5.0-0.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-devel-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-gevolution-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-perl-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-silc-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-tcl-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgaim-remote0-devel-1.5.0-0.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gaim-", release:"MDK10.1")
 || rpm_exists(rpm:"gaim-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-2102", value:TRUE);
 set_kb_item(name:"CVE-2005-2103", value:TRUE);
 set_kb_item(name:"CVE-2005-2370", value:TRUE);
}
exit(0, "Host is not affected");
