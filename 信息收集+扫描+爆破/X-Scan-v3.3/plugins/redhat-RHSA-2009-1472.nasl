
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41963);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1472: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1472");
 script_set_attribute(attribute: "description", value: '
  Updated xen packages that fix a security issue and multiple bugs are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Xen is an open source virtualization framework. Virtualization allows users
  to run guest operating systems in virtual machines on top of a host
  operating system.

  The pyGrub boot loader did not honor the "password" option in the grub.conf
  file for para-virtualized guests. Users with access to a guest\'s console
  could use this flaw to bypass intended access restrictions and boot the
  guest with arbitrary kernel boot options, allowing them to get root
  privileges in the guest\'s operating system. With this update, pyGrub
  correctly honors the "password" option in grub.conf for para-virtualized
  guests. (CVE-2009-3525)

  This update also fixes the following bugs:

  * rebooting para-virtualized guests sometimes caused those guests to crash
  due to a race condition in the xend node control daemon. This update fixes
  this race condition so that rebooting guests no longer potentially causes
  them to crash and fail to reboot. (BZ#525141)

  * due to a race condition in the xend daemon, a guest could disappear from
  the list of running guests following a reboot, even though the guest
  rebooted successfully and was running. This update fixes this race
  condition so that guests always reappear in the guest list following a
  reboot. (BZ#525143)

  * attempting to use PCI pass-through to para-virtualized guests on certain
  kernels failed with a "Function not implemented" error message. As a
  result, users requiring PCI pass-through on para-virtualized guests were
  not able to update the xen packages without also updating the kernel and
  thus requiring a reboot. These updated packages enable PCI pass-through for
  para-virtualized guests so that users do not need to upgrade the kernel in
  order to take advantage of PCI pass-through functionality. (BZ#525149)

  All Xen users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the xend service must be restarted for this update to take
  effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1472.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-3525");
script_summary(english: "Check for the version of the xen packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xen-libs-3.0.3-94.el5_4.1", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xen-libs-3.0.3-94.el5_4.1", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
