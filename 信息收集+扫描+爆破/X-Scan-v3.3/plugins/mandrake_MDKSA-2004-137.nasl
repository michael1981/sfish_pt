
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15793);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:137-1: libxpm4");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:137-1 (libxpm4).");
 script_set_attribute(attribute: "description", value: "The XPM library which is part of the XFree86/XOrg project is used
by several GUI applications to process XPM image files.
A source code review of the XPM library, done by Thomas Biege of the
SuSE Security-Team revealed several different kinds of bugs. These
bugs include integer overflows, out-of-bounds memory access, shell
command execution, path traversal, and endless loops.
These bugs can be exploited by remote and/or local attackers to gain
access to the system or to escalate their local privileges, by using a
specially crafted xpm image.
Update:
The previous libxpm4 update had a linking error that resulted in a missing
s_popen symbol error running applications dependant on the library. In
addition, the file path checking in the security updates prevented some
applications, like gimp-2.0 from being able to save xpm format images.
Updated packages are patched to correct all these issues.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:137-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

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

if ( rpm_check( reference:"libxpm4-3.4k-27.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.3.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-28.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-28.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-3.4k-27.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libxpm4-devel-3.4k-27.3.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
