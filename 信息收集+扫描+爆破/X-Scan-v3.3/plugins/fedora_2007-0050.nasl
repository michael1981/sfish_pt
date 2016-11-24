
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-0050
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27650);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2007-0050: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-0050 (galeon)");
 script_set_attribute(attribute: "description", value: "Galeon is a web browser built around Gecko (Mozilla's rendering
engine) and Necko (Mozilla's networking engine). It's a GNOME web
browser, designed to take advantage of as many GNOME technologies as
makes sense. Galeon was written to do just one thing - browse the web.

-
Update Information:

- Rebuilt with latest firefox package (gecko-libs 1.8.1.4)

");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the galeon package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"galeon-2.0.3-9.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
