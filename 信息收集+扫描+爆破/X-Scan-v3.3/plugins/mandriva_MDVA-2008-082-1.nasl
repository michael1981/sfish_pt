
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36475);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2008:082-1: timezone");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2008:082-1 (timezone).");
 script_set_attribute(attribute: "description", value: "Automatic mirror geolocation in drakxtools-backend in Mandriva
Linux 2008.1 would fail for some locales, because it uses backward
compatibility timezone names for which there were no zone.tab entries
in timezone (bug #40184), this makes software like urpmi to not select
optimal mirrors in its automatic media/mirrors addition mode.
This update makes timezone provide backward timezone name entries in
zone.tab file to solve this issue.
Additionaly, updated timezone packages are being provided for older
Mandriva Linux systems that do not contain the new Daylight Savings
Time information for 2008 and later for certain time zones.
Update:
The previous timezone update for Mandriva Linux 2008 Spring triggered
a bug in gnome-panel, making it immediately crash when the Gnome
session was started. This new update works around the gnome-panel bug.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2008:082-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the timezone package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"timezone-2008c-1.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"timezone-java-2008c-1.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
