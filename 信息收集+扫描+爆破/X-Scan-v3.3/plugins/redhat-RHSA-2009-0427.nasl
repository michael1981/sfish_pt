
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36177);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0427: libvolume_id");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0427");
 script_set_attribute(attribute: "description", value: '
  Updated udev packages that fix one security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  udev provides a user-space API and implements a dynamic device directory,
  providing only the devices present on the system. udev replaces devfs in
  order to provide greater hot plug functionality. Netlink is a datagram
  oriented service, used to transfer information between kernel modules and
  user-space processes.

  It was discovered that udev did not properly check the origin of Netlink
  messages. A local attacker could use this flaw to gain root privileges via
  a crafted Netlink message sent to udev, causing it to create a
  world-writable block device file for an existing system block device (for
  example, the root file system). (CVE-2009-1185)

  Red Hat would like to thank Sebastian Krahmer of the SUSE Security Team for
  responsibly reporting this flaw.

  Users of udev are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. After installing the
  update, the udevd daemon will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0427.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1185");
script_summary(english: "Check for the version of the libvolume_id packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libvolume_id-095-14.20.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libvolume_id-devel-095-14.20.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"udev-095-14.20.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
