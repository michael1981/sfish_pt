
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-4778
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29795);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2007-4778: gallery2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-4778 (gallery2)");
 script_set_attribute(attribute: "description", value: "The base Gallery 2 installation - the equivalent of upstream's -minimal
package.  This package requires a database to be operational.  Acceptable
database backends include MySQL v 3.x, MySQL v 4.x, PostgreSQL v 7.x,
PostgreSQL v 8.x, Oracle 9i, Oracle 10g, DB2, and MS SQL Server.  All given
package versions are minimums, greater package versions are acceptable.

-
Update Information:

Gallery 2.2.4 addresses the following security vulnerabilities:


Update information :

* Publish XP module - Fixed unauthorized album creation and file uploads.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the gallery2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gallery2-2.2.4-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
