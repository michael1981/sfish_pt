
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3383
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36091);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-3383: mapserver");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3383 (mapserver)");
 script_set_attribute(attribute: "description", value: "Mapserver is an internet mapping program that converts GIS data to
map images in real time. With appropriate interface pages,
Mapserver can provide an interactive internet map based on
custom GIS data.

-
Update Information:

The releases contain fixes for issues discovered in an audit of the CGI by a 3r
d
party   (tickets #2939, #2941, #2942, #2943 and #2944). The issues are detailed
at:      [9]http://trac.osgeo.org/mapserver/ticket/2939
[10]http://trac.osgeo.org/mapserver/ticket/2941
[11]http://trac.osgeo.org/mapserver/ticket/2942
[12]http://trac.osgeo.org/mapserver/ticket/2943
[13]http://trac.osgeo.org/mapserver/ticket/2944    Also provided is support for
RFC-56 that addresses tightening up the control of   access to mapfiles and
templates:      [14]http://mapserver.org/development/rfc/ms-rfc-56.html
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0842", "CVE-2009-0843", "CVE-2009-1177");
script_summary(english: "Check for the version of the mapserver package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"mapserver-5.2.2-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
