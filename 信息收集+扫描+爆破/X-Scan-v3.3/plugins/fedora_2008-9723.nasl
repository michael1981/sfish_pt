
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-9723
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34828);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-9723: cobbler");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-9723 (cobbler)");
 script_set_attribute(attribute: "description", value: "
Cobbler is a network boot and update server.  Cobbler
supports PXE, provisioning virtualized images, and
reinstalling existing Linux machines.  The last two
modes require a helper tool called 'koan' that
integrates with cobbler.  Cobbler's advanced features
include importing distributions from DVDs and rsync
mirrors, kickstart templating, integrated yum
mirroring, and built-in DHCP/DNS Management.  Cobbler has
a Python and XMLRPC API for integration with other
applications.

-
Update Information:

Fixes a security vulnerability where a CobblerWeb user (if so configured) can
import a Python module via a web-edited Cheetah template and run commands as
root.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the cobbler package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"cobbler-1.2.9-1.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
