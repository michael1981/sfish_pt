
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1340
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27710);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1340: GraphicsMagick");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1340 (GraphicsMagick)");
 script_set_attribute(attribute: "description", value: "GraphicsMagick is a comprehensive image processing package which is initially
based on ImageMagick 5.5.2, but which has undergone significant re-work by
the GraphicsMagick Group to significantly improve the quality and performance
of the software.

-
Update Information:

Maintainance update fixing several security issues and bugs.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2005-4601", "CVE-2006-0082", "CVE-2006-4144", "CVE-2006-5456", "CVE-2007-1797");
script_summary(english: "Check for the version of the GraphicsMagick package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"GraphicsMagick-1.1.8-2.fc7", release:"FC7") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
