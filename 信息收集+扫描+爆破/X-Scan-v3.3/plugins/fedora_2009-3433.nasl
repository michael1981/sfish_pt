
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3433
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37865);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-3433: xine-lib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3433 (xine-lib)");
 script_set_attribute(attribute: "description", value: "This package contains the Xine library.  It can be used to play back
various media, decode multimedia files from local disk drives, and display
multimedia streamed over the Internet. It interprets many of the most
common multimedia formats available - and some uncommon formats, too.

-
Update Information:

Maintenance release. Fixes two security problems (CVE-2009-0385, CVE-2009-1274)
and a few miscellaneous bugs.    See the upstream changelog for details:
[9]http://sourceforge.net/project/shownotes.php?group_id=9655&release_id=673233
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1274");
script_summary(english: "Check for the version of the xine-lib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xine-lib-1.1.16.3-1.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
