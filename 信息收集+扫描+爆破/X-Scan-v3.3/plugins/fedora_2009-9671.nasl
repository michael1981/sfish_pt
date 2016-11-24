
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9671
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(41610);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-9671: xmp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9671 (xmp)");
 script_set_attribute(attribute: "description", value: "The Extended Module Player is a modplayer for Unix-like systems that plays
over 80 mainstream and obscure module formats from Amiga, Atari, Acorn,
Apple IIgs and PC, including Protracker (MOD), Scream Tracker 3 (S3M), Fast
Tracker II (XM) and Impulse Tracker (IT) files.

-
Update Information:

Update to latest stable release. Multiple bugfixes and memory leak fixes. Fixes
for buffer overflows in DTT and OXM loaders.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-6731", "CVE-2007-6732");
script_summary(english: "Check for the version of the xmp package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"xmp-2.7.1-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
