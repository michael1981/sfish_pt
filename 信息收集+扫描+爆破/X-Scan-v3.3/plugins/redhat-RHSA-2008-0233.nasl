
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32161);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0233: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0233");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * the absence of a protection mechanism when attempting to access a
  critical section of code has been found in the Linux kernel open file
  descriptors control mechanism, fcntl. This could allow a local unprivileged
  user to simultaneously execute code, which would otherwise be protected
  against parallel execution. As well, a race condition when handling locks
  in the Linux kernel fcntl functionality, may have allowed a process
  belonging to a local unprivileged user to gain re-ordered access to the
  descriptor table. (CVE-2008-1669, Important)

  * a possible hypervisor panic was found in the Linux kernel. A privileged
  user of a fully virtualized guest could initiate a stress-test File
  Transfer Protocol (FTP) transfer between the guest and the hypervisor,
  possibly leading to hypervisor panic. (CVE-2008-1619, Important)

  * the absence of a protection mechanism when attempting to access a
  critical section of code, as well as a race condition, have been found
  in the Linux kernel file system event notifier, dnotify. This could allow a
  local unprivileged user to get inconsistent data, or to send arbitrary
  signals to arbitrary system processes. (CVE-2008-1375, Important)

  Red Hat would like to thank Nick Piggin for responsibly disclosing the
  following issue:

  * when accessing kernel memory locations, certain Linux kernel drivers
  registering a fault handler did not perform required range checks. A local
  unprivileged user could use this flaw to gain read or write access to
  arbitrary kernel memory, or possibly cause a kernel crash.
  (CVE-2008-0007, Important)

  * the absence of sanity-checks was found in the hypervisor block backend
  driver, when running 32-bit paravirtualized guests on a 64-bit host. The
  number of blocks to be processed per one request from guest to host, or
  vice-versa, was not checked for its maximum value, which could have allowed
  a local privileged user of the guest operating system to cause a denial of
  service. (CVE-2007-5498, Important)

  * it was discovered that the Linux kernel handled string operations in the
  opposite way to the GNU Compiler Collection (GCC). This could allow a local
  unprivileged user to cause memory corruption. (CVE-2008-1367, Low)

  As well, these updated packages fix the following bugs:

  * on IBM System z architectures, when running QIOASSIST enabled QDIO
  devices in an IBM z/VM environment, the output queue stalled under heavy
  load. This caused network performance to degrade, possibly causing network
  hangs and outages.

  * multiple buffer overflows were discovered in the neofb video driver. It
  was not possible for an unprivileged user to exploit these issues, and as
  such, they have not been handled as security issues.

  * when running Microsoft Windows in a HVM, a bug in vmalloc/vfree caused
  network performance to degrade.

  * on certain architectures, a bug in the libATA sata_nv driver may have
  caused infinite reboots, and an "ata1: CPB flags CMD err flags 0x11" error.

  * repeatedly hot-plugging a PCI Express card may have caused "Bad DLLP"
  errors.

  * a NULL pointer dereference in NFS, which may have caused applications to
  crash, has been resolved.

  * when attempting to kexec reboot, either manually or via a panic-triggered
  kdump, the Unisys ES7000/one hanged after rebooting in the new kernel,
  after printing the "Memory: 32839688k/33685504k available" line.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0233.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5498", "CVE-2008-0007", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1619", "CVE-2008-1669");
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

if ( rpm_check( reference:"kernel-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-53.1.19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
