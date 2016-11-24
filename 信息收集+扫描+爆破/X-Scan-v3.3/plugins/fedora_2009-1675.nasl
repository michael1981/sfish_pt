
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1675
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35735);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-1675: trickle");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1675 (trickle)");
 script_set_attribute(attribute: "description", value: "trickle is a portable lightweight userspace bandwidth shaper.
It can run in collaborative mode or in stand alone mode.

trickle works by taking advantage of the unix loader preloading.
Essentially it provides, to the application,
a new version of the functionality that is required
to send and receive data through sockets.
It then limits traffic based on delaying the sending
and receiving of data over a socket.
trickle runs entirely in userspace and does not require root privileges.

-
Update Information:

New patch for CVE-2009-0415 Fix for #484065 - CVE-2009-0415 trickle: Possibilit
y
to load arbitrary code from current working directory
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0415");
script_summary(english: "Check for the version of the trickle package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"trickle-1.07-7.fc9", release:"FC9") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
