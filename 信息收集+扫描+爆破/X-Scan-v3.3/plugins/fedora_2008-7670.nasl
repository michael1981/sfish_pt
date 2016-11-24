
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7670
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34141);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-7670: rpy");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7670 (rpy)");
 script_set_attribute(attribute: "description", value: "RPy provides a robust Python interface to the R
programming language.  It can manage all kinds of R objects and can
execute arbitrary R functions. All the errors from the R language are
converted to Python exceptions.

-
Update Information:

Update to R 2.7.2, also fixes security issue with unsafe temp directory handlin
g
in javareconf script.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the rpy package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"rpy-1.0.3-3.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
