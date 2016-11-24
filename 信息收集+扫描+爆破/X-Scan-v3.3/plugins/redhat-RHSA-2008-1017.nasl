
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35179);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-1017: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-1017");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that resolve several security issues and fix
  various bugs are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  * Olaf Kirch reported a flaw in the i915 kernel driver. This flaw could,
  potentially, lead to local privilege escalation. Note: the flaw only
  affects systems based on the Intel G33 Express Chipset and newer.
  (CVE-2008-3831, Important)

  * Miklos Szeredi reported a missing check for files opened with O_APPEND in
  the sys_splice(). This could allow a local, unprivileged user to bypass the
  append-only file restrictions. (CVE-2008-4554, Important)

  * a deficiency was found in the Linux kernel Stream Control Transmission
  Protocol (SCTP) implementation. This could lead to a possible denial of
  service if one end of a SCTP connection did not support the AUTH extension.
  (CVE-2008-4576, Important)

  In addition, these updated packages fix the following bugs:

  * on Itanium   systems, when a multithreaded program was traced using the
  command "strace -f", messages such as

  PANIC: attached pid 10740 exited
  PANIC: handle_group_exit: 10740 leader 10721
  ...

  will be displayed, and after which the trace would stop. With these
  updated packages, "strace -f" command no longer results in these error
  messages, and strace terminates normally after tracing all threads.

  * on big-endian systems such as PowerPC, the getsockopt() function
  incorrectly returned 0 depending on the parameters passed to it when the
  time to live (TTL) value equaled 255.

  * when using an NFSv4 file system, accessing the same file with two
  separate processes simultaneously resulted in the NFS client process
  becoming unresponsive.

  * on AMD64 and Intel   64 hypervisor-enabled systems, when a syscall
  correctly returned \'-1\' in code compiled on Red Hat Enterprise Linux 5, the
  same code, when run with the strace utility, would incorrectly return an
  invalid return value. This has been fixed: on AMD64 and Intel   64
  hypervisor-enabled systems, syscalls in compiled code return the same,
  correct values as syscalls run with strace.

  * on the Itanium   architecture, fully-virtualized guest domains created
  using more than 64 GB of memory caused other guest domains not to receive
  interrupts. This caused soft lockups on other guests. All guest domains are
  now able to receive interrupts regardless of their allotted memory.

  * when user-space used SIGIO notification, which was not disabled before
  closing a file descriptor and was then re-enabled in a different process,
  an attempt by the kernel to dereference a stale pointer led to a kernel
  crash. With this fix, such a situation no longer causes a kernel crash.

  * modifications to certain pages made through a memory-mapped region could
  have been lost in cases when the NFS client needed to invalidate the page
  cache for that particular memory-mapped file.

  * fully-virtualized Windows   guests became unresponsive due to the vIOSAPIC
  component being multiprocessor-unsafe. With this fix, vIOSAPIC is
  multiprocessor-safe and Windows guests do not become unresponsive.

  * on certain systems, keyboard controllers could not withstand continuous
  requests to switch keyboard LEDs on or off. This resulted in some or all
  key presses not being registered by the system.

  * on the Itanium   architecture, setting the "vm.nr_hugepages" sysctl
  parameter caused a kernel stack overflow resulting in a kernel panic, and
  possibly stack corruption. With this fix, setting vm.nr_hugepages works
  correctly.

  * hugepages allow the Linux kernel to utilize the multiple page size
  capabilities of modern hardware architectures. In certain configurations,
  systems with large amounts of memory could fail to allocate most of this
  memory for hugepages even if it was free. This could result, for example,
  in database restart failures.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-1017.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3831", "CVE-2008-4554", "CVE-2008-4576");
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

if ( rpm_check( reference:"kernel-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-92.1.22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
