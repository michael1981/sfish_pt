
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-3712
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36175);
 script_version ("$Revision: 1.4 $");
script_name(english: "Fedora 9 2009-3712: udev");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-3712 (udev)");
 script_set_attribute(attribute: "description", value: "The udev package contains an implementation of devfs in
userspace using sysfs and netlink.

-
Update Information:

udev provides a user-space API and implements a dynamic device directory,
providing only the devices present on the system. udev replaces devfs in order
to provide greater hot plug functionality. Netlink is a datagram oriented
service, used to transfer information between kernel modules and user-space
processes.    It was discovered that udev did not properly check the origin of
Netlink messages. A local attacker could use this flaw to gain root privileges
via a crafted Netlink message sent to udev, causing it to create a world-
writable block device file for an existing system block device (for example, th
e
root file system). (CVE-2009-1185)    An integer overflow flaw, potentially
leading to heap-based buffer overflow was found in one of the utilities
providing functionality of the udev device information interface. An attacker
could use this flaw to cause a denial of service, or possibly, to execute
arbitrary code by providing a specially-crafted arguments as input to this
utility. (CVE-2009-1186)    Thanks to Sebastian Krahmer of the SUSE Security
Team for responsibly reporting this flaw.    Users of udev are advised to
upgrade to these updated packages, which contain a backported patch to correct
this issue. After installing the update, the udevd daemon will be restarted
automatically.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1185", "CVE-2009-1186");
script_summary(english: "Check for the version of the udev package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"udev-124-4.fc9", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
