
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1092
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35560);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2009-1092: glpi");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1092 (glpi)");
 script_set_attribute(attribute: "description", value: "GLPI is the Information Resource-Manager with an additional Administration-
Interface. You can use it to build up a database with an inventory for your
company (computer, software, printers...). It has enhanced functions to make
the daily life for the administrators easier, like a job-tracking-system with
mail-notification and methods to build a database with basic information
about your network-topology.

-
Update Information:

Upstream Changelog :    Version 0.71.5  - Regression on list order    Version
0.71.4  - [SECURITY] SQL injection problem  - Manage UTF8 filename  - Search
Engine fails for Computer / Peripheral  - Error in VNC display on report infoco
m
- RDV are note display in the planning
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the glpi package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"glpi-0.71.5-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
