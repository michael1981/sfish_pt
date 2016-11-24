
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-1518
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36955);
 script_version ("$Revision: 1.1 $");
script_name(english: "Fedora 10 2009-1518: python-fedora");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-1518 (python-fedora)");
 script_set_attribute(attribute: "description", value: "Python modules that help with building Fedora Services.  This includes a JSON
based auth provider for authenticating against FAS2 over the network and a
client that handles communication with the servers.  The client module can
be used to build programs that communicate with Fedora Infrastructure's
TurboGears Applications such as Bodhi, PackageDB, MirrorManager, and FAS2.

-
Update Information:

This release includes a bugfix to the
fedora.client.AccountSystem().verify_password() method.  verify_password() was
incorrectly returning True (username, password combination was correct) for any
input.  Although no known code is using this method to verify a user's account
with the Fedora Account System, the existence of the method and the fact that
anyone using this would be allowing users due to the bug makes this a high
priority bug to fix.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the python-fedora package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"python-fedora-0.3.9-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
