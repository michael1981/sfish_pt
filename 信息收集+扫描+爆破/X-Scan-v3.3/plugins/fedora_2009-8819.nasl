
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8819
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40685);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 11 2009-8819: ocsinventory");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8819 (ocsinventory)");
 script_set_attribute(attribute: "description", value: "Open Computer and Software Inventory Next Generation is an application
designed to help a network or system administrator keep track of the
computers configuration and software that are installed on the network.

OCS Inventory is also able to detect all active devices on your network,
such as switch, router, network printer and unattended devices.

OCS Inventory NG includes package deployment feature on client computers.

ocsinventory is a metapackage that will install the communication server,
the administration console and the database server (MySQL).

-
Update Information:

A security issue has been found in GUI
[9]http://seclists.org/fulldisclosure/2009/Aug/0143.html
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the ocsinventory package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"ocsinventory-1.02.1-3.fc11", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
