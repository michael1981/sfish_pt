
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36115);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0411: device");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0411");
 script_set_attribute(attribute: "description", value: '
  Updated device-mapper-multipath packages that fix a security issue are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The device-mapper multipath packages provide tools to manage multipath
  devices by issuing instructions to the device-mapper multipath kernel
  module, and by managing the creation and removal of partitions for
  device-mapper devices.

  It was discovered that the multipathd daemon set incorrect permissions on
  the socket used to communicate with command line clients. An unprivileged,
  local user could use this flaw to send commands to multipathd, resulting in
  access disruptions to storage devices accessible via multiple paths and,
  possibly, file system corruption on these devices. (CVE-2009-0115)

  Users of device-mapper-multipath are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue. The
  multipathd service must be restarted for the changes to take effect.

  Important: the version of the multipathd daemon in Red Hat Enterprise Linux
  5 has a known issue which may cause a machine to become unresponsive when
  the multipathd service is stopped. This issue is tracked in the Bugzilla
  bug #494582; a link is provided in the References section of this erratum.
  Until this issue is resolved, we recommend restarting the multipathd
  service by issuing the following commands in sequence:

  # killall -KILL multipathd

  # service multipathd restart


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0411.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0115");
script_summary(english: "Check for the version of the device packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"device-mapper-multipath-0.4.7-23.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kpartx-0.4.7-23.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"device-mapper-multipath-0.4.5-31.el4_7.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
