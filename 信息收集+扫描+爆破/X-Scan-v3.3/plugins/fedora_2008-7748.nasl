
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-7748
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34150);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 9 2008-7748: PackageKit");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-7748 (PackageKit)");
 script_set_attribute(attribute: "description", value: "PackageKit is a D-Bus abstraction layer that allows the session user
to manage packages in a secure way using a cross-distro,
cross-architecture API.

-
Update Information:

This fedora-release update introduces a new set of Fedora Updates and Updates
Testing repo definitions.  These new definitions point to new URLS for our
update content signed with a new key.  This update also provides Fedora 8 and
9's new package signing keys.  This update is a transitional update to direct
users at the rest of the updates in the new locations.  It will be superseded b
y
further fedora-release updates at a future date.    The Fedora 9 update also
includes new versions of PackageKit and gnome-packagekit to better handle
importing of our new key.    If you are using PackageKit it is recommended that
you reboot after installing this update so that PackageKit can get a fresh look
at the new repodata from the new repo definitions.    See
[9]https://fedoraproject.org/wiki/Enabling_new_signing_key for more details.  T
his
update adds the ia64 secondary arch key as well as arranges  GPG keys by arch
and refers to them by arch in yum repo configs.  This allows the secondary arch
key to only be used on secondary arches  and allows the fedora-release package
to continue to be noarch.    Also this update changes the commented out baseurl
from  download.fedora.redhat.com to download.fedoraproject.org.
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the PackageKit package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"PackageKit-0.2.5-1.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
