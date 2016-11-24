
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-491
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25181);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 5 2007-491: gimp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-491 (gimp)");
 script_set_attribute(attribute: "description", value: "GIMP (GNU Image Manipulation Program) is a powerful image composition and
editing program, which can be extremely useful for creating logos and other
graphics for webpages. GIMP has many of the tools and filters you would expect
to find in similar commercial offerings, and some interesting extras as well.
GIMP provides a large image manipulation toolbox, including channel operations
and layers, effects, sub-pixel imaging and anti-aliasing, and conversions, all
with multi-level undo.

Update Information:

The GIMP package in Fedora includes a helper script
/usr/sbin/gimp-plugin-mgr for plugins contained in other
packages, for example, xsane-gimp. This script manages
symlinks from the GIMP plugin directory (which may change
between upgrades) to the actual location of the plugins.

A bug has been fixed in this erratum of GIMP that was in all
older GIMP packages. The bug concerns the execution order in
which the symlinks are installed and removed, causing the
symlinks to vanish when the GIMP package is updated.

Although this GIMP erratum has the execution order fixed,
due to the nature of the problem it will show up once more
when updating from an affected version to a fixed version.
To add these symlinks back in, run this command, providing
the root password when prompted:

su -c '/usr/sbin/gimp-plugin-mgr --install '*''
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the gimp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gimp-devel-2.2.14-5.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gimp-libs-2.2.14-5.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gimp-2.2.14-5.fc5", release:"FC5") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
