
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-2343
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27767);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-2343: t1lib");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-2343 (t1lib)");
 script_set_attribute(attribute: "description", value: "T1lib is a rasterizer library for Adobe Type 1 Fonts. It supports
rotation and transformation, kerning underlining and antialiasing. It
does not depend on X11, but does provides some special functions for
X11.

AFM-files can be generated from Type 1 font files and font subsetting
is possible.

-
Update Information:

This is most likely not exploitable on Fedora, due to FORTIFY_SOURCE protection
, as the overflow is strcat() call which is protected.

This update has a patch that avoids the call where the overflow would occur.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-4033");
script_summary(english: "Check for the version of the t1lib package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"t1lib-5.1.1-3.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
