
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-662
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25865);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 6 2007-662: vixie-cron");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-662 (vixie-cron)");
 script_set_attribute(attribute: "description", value: "The vixie-cron package contains the Vixie version of cron.  Cron is a
standard UNIX daemon that runs specified programs at scheduled times.
Vixie cron adds better security and more powerful configuration
options to the standard version of cron.

Update Information:

By creating a hardlink to /etc/crontab, cron will stop
executing the
/etc/crontab file and deposit an error message in /var/log/cron.


");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the vixie-cron package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"vixie-cron-4.1-69.fc6", release:"FC6") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
