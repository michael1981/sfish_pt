
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7572
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34136);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 8 2008-7572: xine-lib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7572 (xine-lib)");
 script_set_attribute(attribute: "description", value: "This package contains the Xine library. Xine is a free multimedia player.
It can play back various media. It also decodes multimedia files from local
disk drives, and displays multimedia streamed over the Internet. It
interprets many of the most common multimedia formats available - and some
of the most uncommon formats, too.  --with/--without rpmbuild options
(some default values depend on target distribution): aalib, caca, directfb,
imagemagick, freetype, antialiasing (with freetype), pulseaudio, xcb.

-
Update Information:

This release fixes multiple bugs and security issues:  - DoS via corrupted Ogg
files (CVE-2008-3231)  - multiple possible buffer overflows detailed in
oCERT-2008-008    For more details, see:
[9]http://sourceforge.net/project/shownotes.php?release_id=619869&group_id=9655
[10]http://www.ocert.org/advisories/ocert-2008-008.html    NOTE: A coordinated
release with 3rd-party repos was not possible, so this update may result in
dependency issues with currently-installed xine-lib-extras-* rpms.  This
temporary problem will be rectified asap.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-0073", "CVE-2008-1482", "CVE-2008-1878", "CVE-2008-3231");
script_summary(english: "Check for the version of the xine-lib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xine-lib-1.1.15-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
