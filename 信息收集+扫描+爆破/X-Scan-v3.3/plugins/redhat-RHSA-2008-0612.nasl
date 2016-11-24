
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33830);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2008-0612: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0612");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * a possible kernel memory leak was found in the Linux kernel Simple
  Internet Transition (SIT) INET6 implementation. This could allow a local
  unprivileged user to cause a denial of service. (CVE-2008-2136, Important)

  * a flaw was found in the Linux kernel setrlimit system call, when setting
  RLIMIT_CPU to a certain value. This could allow a local unprivileged user
  to bypass the CPU time limit. (CVE-2008-1294, Moderate)

  * multiple NULL pointer dereferences were found in various Linux kernel
  network drivers. These drivers were missing checks for terminal validity,
  which could allow privilege escalation. (CVE-2008-2812, Moderate)

  These updated packages fix the following bugs:

  * the GNU libc stub resolver is a minimal resolver that works with Domain
  Name System (DNS) servers to satisfy requests from applications for names.
  The GNU libc stub resolver did not specify a source UDP port, and therefore
  used predictable port numbers. This could have made DNS spoofing attacks
  easier.

  The Linux kernel has been updated to implement random UDP source ports
  where none are specified by an application. This allows applications, such
  as those using the GNU libc stub resolver, to use random UDP source ports,
  helping to make DNS spoofing attacks harder.

  * when using certain hardware, a bug in UART_BUG_TXEN may have caused
  incorrect hardware detection, causing data flow to "/dev/ttyS1" to hang.

  * a 50-75% drop in NFS server rewrite performance, compared to Red Hat
  Enterprise Linux 4.6, has been resolved.

  * due a bug in the fast userspace mutex code, while one thread fetched a
  pointer, another thread may have removed it, causing the first thread to
  fetch the wrong pointer, possibly causing a system crash.

  * on certain Hitachi hardware, removing the "uhci_hcd" module caused a
  kernel oops, and the following error:

  BUG: warning at arch/ia64/kernel/iosapic.c:1001/iosapic_unregister_intr()

  Even after the "uhci_hcd" module was reloaded, there was no access to USB
  devices. As well, on systems that have legacy interrupts,
  "acpi_unregister_gsi" incorrectly called "iosapci_unregister_intr()",
  causing warning messages to be logged.

  * when a page was mapped with mmap(), and "PROT_WRITE" was the only
  "prot" argument, the first read of that page caused a segmentation fault.
  If the page was read after it was written to, no fault occurred. This was
  incompatible with the Red Hat Enterprise Linux 4 behavior.

  * due to a NULL pointer dereference in powernowk8_init(), a panic may
  have occurred.

  * certain error conditions handled by the bonding sysfs interface could
  have left rtnl_lock() unbalanced, either by locking and returning without
  unlocking, or by unlocking when it did not lock, possibly causing a
  "kernel: RTNL: assertion failed at net/core/fib_rules.c" error.

  * the kernel currently expects a maximum of six Machine Check Exception
  (MCE) banks to be exposed by a CPU. Certain CPUs have 7 or more, which may
  have caused the MCE to be incorrectly reported.

  * a race condition in UNIX domain sockets may have caused recv() to return
  zero. For clusters, this may have caused unexpected failovers.

  * msgrcv() frequently returned an incorrect "ERESTARTNOHAND (514)" error
  number.

  * on certain Intel Itanium-based systems, when kdump was configured to halt
  the system after a dump operation, after the "System halted." output, the
  kernel continued to output endless "soft lockup" messages.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0612.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1294", "CVE-2008-2136", "CVE-2008-2812");
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

if ( rpm_check( reference:"kernel-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-92.1.10.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
