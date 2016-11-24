
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-4594
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29810);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2007-4594: imlib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-4594 (imlib)");
 script_set_attribute(attribute: "description", value: "Imlib is a display depth independent image loading and rendering library.
Imlib is designed to simplify and speed up the process of loading images and
obtaining X Window System drawables. Imlib provides many simple manipulation
routines which can be used for common operations.

The imlib package also contains the imlib_config program, which you can use to
configure the Imlib image loading and rendering library. Imlib_config can be
used to control how Imlib uses color and handles gamma corrections, etc.

Install imlib if you need an image loading and rendering library for X11R6, or
if you are installing GNOME.

-
Update Information:

This update includes a fix for a denial-of-service issue (CVE-2007-3568) whereb
y an attacker who could get an imlib-using user to view a  specially-crafted BM
P image could cause the user's CPU to go into an infinite loop.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3568");
script_summary(english: "Check for the version of the imlib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"imlib-1.9.15-6.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
