
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35300);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0003: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0003");
 script_set_attribute(attribute: "description", value: '
  Updated xen packages that resolve several security issues and a bug are now
  available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The xen packages contain the Xen tools and management daemons needed to
  manage virtual machines running on Red Hat Enterprise Linux.

  Xen was found to allow unprivileged DomU domains to overwrite xenstore
  values which should only be changeable by the privileged Dom0 domain. An
  attacker controlling a DomU domain could, potentially, use this flaw to
  kill arbitrary processes in Dom0 or trick a Dom0 user into accessing the
  text console of a different domain running on the same host. This update
  makes certain parts of the xenstore tree read-only to the unprivileged DomU
  domains. (CVE-2008-4405)

  It was discovered that the qemu-dm.debug script created a temporary file in
  /tmp in an insecure way. A local attacker in Dom0 could, potentially, use
  this flaw to overwrite arbitrary files via a symlink attack. Note: This
  script is not needed in production deployments and therefore was removed
  and is not shipped with updated xen packages. (CVE-2008-4993)

  This update also fixes the following bug:

  * xen calculates its running time by adding the hypervisor\'s up-time to the
  hypervisor\'s boot-time record. In live migrations of para-virtualized
  guests, however, the guest would over-write the new hypervisor\'s boot-time
  record with the boot-time of the previous hypervisor. This caused
  time-dependent processes on the guests to fail (for example, crond would
  fail to start cron jobs). With this update, the new hypervisor\'s boot-time
  record is no longer over-written during live migrations.

  All xen users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. The Xen host must be
  restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0003.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4405", "CVE-2008-4993");
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

if ( rpm_check( reference:"xen-libs-3.0.3-64.el5_2.9", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
