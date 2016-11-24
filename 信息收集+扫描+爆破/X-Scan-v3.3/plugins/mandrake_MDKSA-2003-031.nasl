
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14015);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:031-1: usermode");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:031-1 (usermode).");
 script_set_attribute(attribute: "description", value: "The /usr/bin/shutdown command that comes with the usermode package can
be executed by local users to shutdown all running processes and drop
into a root shell. This command is not really needed to shutdown a
system, so it has been removed and all users are encouraged to upgrade.
Please note that the user must have local console access in order to
obtain a root shell in this fashion.
Update:
The previous updated packages did not properly fix the problem. The pam
files that allow a (physically) local user to shutdown were not removed.
This has been corrected.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:031-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the usermode package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"usermode-1.42-8.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"usermode-1.44-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"usermode-consoleonly-1.44-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
