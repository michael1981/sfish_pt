
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0847
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27683);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-0847: php-pear-Structures-DataGrid-DataSource-MDB2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0847 (php-pear-Structures-DataGrid-DataSource-MDB2)");
 script_set_attribute(attribute: "description", value: "This is a DataSource driver for Structures_DataGrid using PEAR::MDB2 and an
SQL query.

-
Update Information:

Security fix: users could manipulate the generated sorting queries
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the php-pear-Structures-DataGrid-DataSource-MDB2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"php-pear-Structures-DataGrid-DataSource-MDB2-0.1.10-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
