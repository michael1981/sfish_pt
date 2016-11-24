
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9293
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34677);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-9293: libgadu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9293 (libgadu)");
 script_set_attribute(attribute: "description", value: "libgadu is intended to make it easy to add Gadu-Gadu communication
support to your software.

-
Update Information:

Security fix for denial of service (crash) via a contact description with a
large length, which triggers a buffer over-read.  Successful exploitation would
require a man-in-the-middle attack or hacking the Gadu-Gadu servers. No known
exploits.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the libgadu package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"libgadu-1.8.2-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
