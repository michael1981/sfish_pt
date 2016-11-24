
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2668
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27788);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-2668: blam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2668 (blam)");
 script_set_attribute(attribute: "description", value: "Blam is a tool that helps you keep track of the growing
number of news feeds distributed as RSS. Blam lets you
subscribe to any number of feeds and provides an easy to
use and clean interface to stay up to date

-
Update Information:

An update to Firefox (version 2.0.0.8) was recently pushed which resolves some
security issues.

Users of Blam and Epiphany Extensions are advised to upgrade to these erratum p
ackages, which have been rebuilt against the updated Firefox packages.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the blam package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"blam-1.8.3-7.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
