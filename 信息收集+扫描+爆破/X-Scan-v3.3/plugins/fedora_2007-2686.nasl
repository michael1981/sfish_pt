
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2686
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27792);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-2686: openvrml");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2686 (openvrml)");
 script_set_attribute(attribute: "description", value: "OpenVRML is a VRML/X3D support library, including a runtime and facilities
for reading and displaying VRML and X3D models.

-
ChangeLog:


Update information :

* Wed Oct 24 2007 Braden McDaniel  <braden endoframe com> - 0.16.6-3
- Updated firefox dependency to 2.0.0.8.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the openvrml package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"openvrml-0.16.6-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
