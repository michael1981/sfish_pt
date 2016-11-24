
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3789
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38185);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 9 2009-3789: prewikka");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3789 (prewikka)");
 script_set_attribute(attribute: "description", value: "Prewikka is a graphical front-end analysis console for the Prelude
Hybrid IDS Framework. Providing numerous features, Prewikka facilitates
the work of users and analysts. It provides alert aggregation and sensor
and hearbeat views, and has user management and configurable filters. It
has access to external tools such as whois and traceroute.

Please read README.fedora for installation instructions.

-
Update Information:

The permissions on the prewikka.conf file are world readable and contain the sq
l
database password used by prewikka. This update makes it readable just by the
apache group.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the prewikka package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"prewikka-0.9.14-2.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
