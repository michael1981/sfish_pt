
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1013
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27687);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-1013: phpPgAdmin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1013 (phpPgAdmin)");
 script_set_attribute(attribute: "description", value: "phpPgAdmin is a fully functional web-based administration utility for
a PostgreSQL database server. It handles all the basic functionality
as well as some advanced features such as triggers, views and
functions (stored procedures). It also has Slony-I support.

-
Update Information:

This version further tightens up security and fixes some issues introduced in t
he 4.1.2 release. All users are strongly encouraged to upgrade.

");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the phpPgAdmin package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"phpPgAdmin-4.1.3-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
