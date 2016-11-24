
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-6025
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(33406);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-6025: glib2");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-6025 (glib2)");
 script_set_attribute(attribute: "description", value: "GLib is the low-level core library that forms the basis
for projects such as GTK+ and GNOME. It provides data structure
handling for C, portability wrappers, and interfaces for such runtime
functionality as an event loop, threads, dynamic loading, and an
object system.

This package provides version 2 of GLib.

-
Update Information:

This update fixes a heap-based overflow caused by incorrect option handling in
pcre (CVE-2008-2371)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-2371");
script_summary(english: "Check for the version of the glib2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"glib2-2.14.6-2.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
