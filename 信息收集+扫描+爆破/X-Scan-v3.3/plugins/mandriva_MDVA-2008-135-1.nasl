
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36787);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVA-2008:135-1: draksnapshot");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVA-2008:135-1 (draksnapshot).");
 script_set_attribute(attribute: "description", value: "This update fixes several issues in draksnapshot:
The draksnapshot applet received the following fixes:
- on desktop startup, it will wait for 30s before checking for
available disc so that notification is positioned at the right place,
on the applet icon
- it prevents crashing if DBus is not reachable, and reports DBus
errors
- it prevents crashing if DBus is active, but HAL is not (#44434)
- if all discs are unmounted, the applet will hide (#41176)
- it prevents running more than once
- it uses HAL in order to detect discs available for backup, thus
fixing detecting some internal SATA discs as discs available for backup
(#41107)
It also uses new icons from Mandriva Linux 2009.0.
The draksnapshot configuration tool also received the following fixes:
- it stops saving config when clicking Close (#39790); one has to
click on Apply in order to save the config
- on first run, it offers backup in mounted disc path, instead of
defaulting to some place in the root filesystem which could previously
be filled up (#39802)
- it no longer offers to configure some obscure advanced options
- it now allows for disabling backups
- it generates anacron-friendly cron files
Update:
An updated draksnapshot is now available for Mandriva Linux 2009.0.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVA-2008:135-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_summary(english: "Check for the version of the draksnapshot package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"draksnapshot-0.19-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"draksnapshot-0.19-2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
