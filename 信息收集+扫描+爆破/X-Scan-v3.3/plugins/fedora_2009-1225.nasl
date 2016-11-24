
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1225
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37279);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2009-1225: gpsdrive");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1225 (gpsdrive)");
 script_set_attribute(attribute: "description", value: "Gpsdrive is a map-based navigation system.
It displays your position on a zoomable map
provided from a NMEA-capable GPS receiver. The maps are autoselected
for the best resolution, depending of your position, and the displayed
image can be zoomed. Maps can be downloaded from the Internet with one
mouse click. The program provides information about speed, direction,
bearing, arrival time, actual position, and target position.
Speech output is also available. MySQL is supported.

-
Update Information:

This update removes several helper scripts: geo-code, geo-nearest, and
gpssmswatch, which have been removed upstream due to security issues. This
update also has a fix for an issue with the splash screen.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-4959", "CVE-2008-5380", "CVE-2008-5703");
script_summary(english: "Check for the version of the gpsdrive package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"gpsdrive-2.09-7.fc10", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
