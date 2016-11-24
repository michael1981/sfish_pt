
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2944
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27820);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2007-2944: glib2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2944 (glib2)");
 script_set_attribute(attribute: "description", value: "GLib is the low-level core library that forms the basis
for projects such as GTK+ and GNOME. It provides data structure
handling for C, portability wrappers, and interfaces for such runtime
functionality as an event loop, threads, dynamic loading, and an
object system.

This package provides version 2 of GLib.

-
Update Information:

The latest stable upstream release of GLib includes a new version of PCRE, whic
h fixes several vulnerabilities.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the glib2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"glib2-2.14.3-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
