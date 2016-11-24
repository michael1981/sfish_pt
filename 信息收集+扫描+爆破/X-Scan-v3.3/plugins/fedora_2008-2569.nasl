
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-2569
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31665);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-2569: xine-lib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-2569 (xine-lib)");
 script_set_attribute(attribute: "description", value: "This package contains the Xine library. Xine is a free multimedia player.
It can play back various media. It also decodes multimedia files from local
disk drives, and displays multimedia streamed over the Internet. It
interprets many of the most common multimedia formats available - and some
of the most uncommon formats, too.  --with/--without rpmbuild options
(some default values depend on target distribution): aalib, caca, directfb,
imagemagick, freetype, antialiasing (with freetype), pulseaudio, xcb.

-
Update Information:


Update information :

* Wed Mar 19 2008 Ville SkyttÃ¤ <ville.skytta at iki.fi> - 1.1.11-1  - 1.1.11
(security update, #438182, CVE-2008-0073).  - Drop jack and wavpack build
conditionals.  - Specfile cleanups.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0073");
script_summary(english: "Check for the version of the xine-lib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xine-lib-1.1.11-1.fc8", release:"FC8") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
