
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40487);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1193: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1193");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * the possibility of a timeout value overflow was found in the Linux kernel
  high-resolution timers functionality, hrtimers. This could allow a local,
  unprivileged user to execute arbitrary code, or cause a denial of service
  (kernel panic). (CVE-2007-5966, Important)

  * a flaw was found in the Intel PRO/1000 network driver in the Linux
  kernel. Frames with sizes near the MTU of an interface may be split across
  multiple hardware receive descriptors. Receipt of such a frame could leak
  through a validation check, leading to a corruption of the length check. A
  remote attacker could use this flaw to send a specially-crafted packet that
  would cause a denial of service or code execution. (CVE-2009-1385,
  Important)

  * Michael Tokarev reported a flaw in the Realtek r8169 Ethernet driver in
  the Linux kernel. This driver allowed interfaces using this driver to
  receive frames larger than could be handled, which could lead to a remote
  denial of service or code execution. (CVE-2009-1389, Important)

  * the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared when a
  setuid or setgid program was executed. A local, unprivileged user could use
  this flaw to bypass the mmap_min_addr protection mechanism and perform a
  NULL pointer dereference attack, or bypass the Address Space Layout
  Randomization (ASLR) security feature. (CVE-2009-1895, Important)

  * Ramon de Carvalho Valle reported two flaws in the Linux kernel eCryptfs
  implementation. A local attacker with permissions to perform an eCryptfs
  mount could modify the metadata of the files in that eCrypfts mount to
  cause a buffer overflow, leading to a denial of service or privilege
  escalation. (CVE-2009-2406, CVE-2009-2407, Important)

  * Konstantin Khlebnikov discovered a race condition in the ptrace
  implementation in the Linux kernel. This race condition can occur when the
  process tracing and the process being traced participate in a core dump. A
  local, unprivileged user could use this flaw to trigger a deadlock,
  resulting in a partial denial of service. (CVE-2009-1388, Moderate)

  Bug fixes:

  * possible host (dom0) crash when installing a Xen para-virtualized guest
  while another para-virtualized guest was rebooting. (BZ#497812)

  * no audit record for a directory removal if the directory and its subtree
  were recursively watched by an audit rule. (BZ#507561)

  * running "echo 1 > /proc/sys/vm/drop_caches" on systems under high memory
  load could cause a kernel panic. (BZ#503692)

  * on 32-bit systems, core dumps for some multithreaded applications did not
  include all thread information. (BZ#505322)

  * a stack buffer used by get_event_name() was not large enough for the nul
  terminator sprintf() writes. This could lead to an invalid pointer or
  kernel panic. (BZ#506906)

  * when using the aic94xx driver, a system with SATA drives may not boot due
  to a bug in libsas. (BZ#506029)

  * incorrect stylus button handling when moving it away then returning it to
  the tablet for Wacom Cintiq 21UX and Intuos tablets. (BZ#508275)

  * CPU "soft lockup" messages and possibly a system hang on systems with
  certain Broadcom network devices and running the Linux kernel from the
  kernel-xen package. (BZ#503689)

  * on 64-bit PowerPC, getitimer() failed for programs using the ITIMER_REAL
  timer and that were also compiled for 64-bit systems (this caused such
  programs to abort). (BZ#510018)

  * write operations could be blocked even when using O_NONBLOCK. (BZ#510239)

  * the "pci=nomsi" option was required for installing and booting Red Hat
  Enterprise Linux 5.2 on systems with VIA VT3364 chipsets. (BZ#507529)

  * shutting down, destroying, or migrating Xen guests with large amounts of
  memory could cause other guests to be temporarily unresponsive. (BZ#512311)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1193.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5966", "CVE-2009-1385", "CVE-2009-1388", "CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407");
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

if ( rpm_check( reference:"kernel-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-128.4.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-128.4.1.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
