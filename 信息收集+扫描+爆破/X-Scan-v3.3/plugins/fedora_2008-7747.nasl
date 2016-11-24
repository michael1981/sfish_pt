
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7747
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34149);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-7747: fedora-release");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7747 (fedora-release)");
 script_set_attribute(attribute: "description", value: "Fedora release files such as yum configs and various /etc/ files that
define the release.

-
Update Information:

This fedora-release update introduces a new set of Fedora Updates and Updates
Testing repo definitions.  These new definitions point to new URLS for our
update content signed with a new key.  This update also provides Fedora 8 and
9's new package signing keys.  This update is a transitional update to direct
users at the rest of the updates in the new locations.  It will be superseded b
y
further fedora-release updates at a future date.    See
[9]https://fedoraproject.org/wiki/Enabling_new_signing_key for more details.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the fedora-release package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"fedora-release-8-6.transition", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
