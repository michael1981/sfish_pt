
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32391);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0275: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0275");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * on AMD64 architectures, the possibility of a kernel crash was discovered
  by testing the Linux kernel process-trace ability. This could allow a local
  unprivileged user to cause a denial of service (kernel crash).
  (CVE-2008-1615, Important)

  * on 64-bit architectures, the possibility of a timer-expiration value
  overflow was found in the Linux kernel high-resolution timers
  functionality, hrtimer. This could allow a local unprivileged user to setup
  a large interval value, forcing the timer expiry value to become negative,
  causing a denial of service (kernel hang). (CVE-2007-6712, Important)

  * the possibility of a kernel crash was found in the Linux kernel IPsec
  protocol implementation, due to improper handling of fragmented ESP
  packets. When an attacker controlling an intermediate router fragmented
  these packets into very small pieces, it would cause a kernel crash on the
  receiving node during packet reassembly. (CVE-2007-6282, Important)

  * a potential denial of service attack was discovered in the Linux kernel
  PWC USB video driver. A local unprivileged user could use this flaw to
  bring the kernel USB subsystem into the busy-waiting state, causing a
  denial of service. (CVE-2007-5093, Low)

  As well, these updated packages fix the following bugs:

  * in certain situations, a kernel hang and a possible panic occurred when
  disabling the cpufreq daemon. This may have prevented system reboots from
  completing successfully.

  * continual "softlockup" messages, which occurred on the guest\'s console
  after a successful save and restore of a Red Hat Enterprise Linux 5
  para-virtualized guest, have been resolved.

  * in the previous kernel packages, the kernel may not have reclaimed NFS
  locks after a system reboot.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0275.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5093", "CVE-2007-6282", "CVE-2007-6712", "CVE-2008-1615");
script_summary(english: "Check for the version of the kernel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-53.1.21.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
