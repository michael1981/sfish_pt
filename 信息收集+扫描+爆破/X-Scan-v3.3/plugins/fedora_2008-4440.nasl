
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-4440
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(32462);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2008-4440: cbrpager");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-4440 (cbrpager)");
 script_set_attribute(attribute: "description", value: "A no-nonsense, simple to use, small viewer for cbr and cbz
(comic book archive) files. As it is written in C,
the executable is small and fast. It views jpg (or jpeg),
gif and png images, and you can zoom in and out.

-
Update Information:

New version 0.9.17 is released:
[9]http://sourceforge.net/forum/forum.php?forum_id=827120
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the cbrpager package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"cbrpager-0.9.17-2.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
