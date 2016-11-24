
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1047
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(30115);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 7 2008-1047: xine-lib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1047 (xine-lib)");
 script_set_attribute(attribute: "description", value: "This package contains the Xine library. Xine is a free multimedia player.
It can play back various media. It also decodes multimedia files from local
disk drives, and displays multimedia streamed over the Internet. It
interprets many of the most common multimedia formats available - and some
of the most uncommon formats, too.  --with/--without rpmbuild options
(some default values depend on target distribution): aalib, caca, directfb,
imagemagick, freetype, antialiasing (with freetype), jack, pulseaudio,
wavpack, xcb.

-
Update Information:

Maintenance/security fix release 1.1.10.
[9]http://sourceforge.net/project/shownotes.php?group_id=9655&release_id=571608
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the xine-lib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xine-lib-1.1.10-1.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
