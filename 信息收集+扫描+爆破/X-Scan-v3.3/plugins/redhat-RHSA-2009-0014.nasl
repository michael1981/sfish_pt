
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35381);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2009-0014: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0014");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that resolve several security issues and fix
  various bugs are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update addresses the following security issues:

  * the sendmsg() function in the Linux kernel did not block during UNIX
  socket garbage collection. This could, potentially, lead to a local denial
  of service. (CVE-2008-5300, Important)

  * when fput() was called to close a socket, the __scm_destroy() function in
  the Linux kernel could make indirect recursive calls to itself. This could,
  potentially, lead to a local denial of service. (CVE-2008-5029, Important)

  * a deficiency was found in the Linux kernel virtual file system (VFS)
  implementation. This could allow a local, unprivileged user to make a
  series of file creations within deleted directories, possibly causing a
  denial of service. (CVE-2008-3275, Moderate)

  * a buffer underflow flaw was found in the Linux kernel IB700 SBC watchdog
  timer driver. This deficiency could lead to a possible information leak. By
  default, the "/dev/watchdog" device is accessible only to the root user.
  (CVE-2008-5702, Low)

  * the hfs and hfsplus file systems code failed to properly handle corrupted
  data structures. This could, potentially, lead to a local denial of
  service. (CVE-2008-4933, CVE-2008-5025, Low)

  * a flaw was found in the hfsplus file system implementation. This could,
  potentially, lead to a local denial of service when write operations were
  performed. (CVE-2008-4934, Low)

  This update also fixes the following bugs:

  * when running Red Hat Enterprise Linux 4.6 and 4.7 on some systems running
  Intel   CPUs, the cpuspeed daemon did not run, preventing the CPU speed from
  being changed, such as not being reduced to an idle state when not in use.

  * mmap() could be used to gain access to beyond the first megabyte of RAM,
  due to insufficient checks in the Linux kernel code. Checks have been added
  to prevent this.

  * attempting to turn keyboard LEDs on and off rapidly on keyboards with
  slow keyboard controllers, may have caused key presses to fail.

  * after migrating a hypervisor guest, the MAC address table was not
  updated, causing packet loss and preventing network connections to the
  guest. Now, a gratuitous ARP request is sent after migration. This
  refreshes the ARP caches, minimizing network downtime.

  * writing crash dumps with diskdump may have caused a kernel panic on
  Non-Uniform Memory Access (NUMA) systems with certain memory
  configurations.

  * on big-endian systems, such as PowerPC, the getsockopt() function
  incorrectly returned 0 depending on the parameters passed to it when the
  time to live (TTL) value equaled 255, possibly causing memory corruption
  and application crashes.

  * a problem in the kernel packages provided by the RHSA-2008:0508 advisory
  caused the Linux kernel\'s built-in memory copy procedure to return the
  wrong error code after recovering from a page fault on AMD64 and Intel 64
  systems. This may have caused other Linux kernel functions to return wrong
  error codes.

  * a divide-by-zero bug in the Linux kernel process scheduler, which may
  have caused kernel panics on certain systems, has been resolved.

  * the netconsole kernel module caused the Linux kernel to hang when slave
  interfaces of bonded network interfaces were started, resulting in a system
  hang or kernel panic when restarting the network.

  * the "/proc/xen/" directory existed even if systems were not running Red
  Hat Virtualization. This may have caused problems for third-party software
  that checks virtualization-ability based on the existence of "/proc/xen/".
  Note: this update will remove the "/proc/xen/" directory on systems not
  running Red Hat Virtualization.

  All Red Hat Enterprise Linux 4 users should upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0014.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-3275", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5300", "CVE-2008-5702");
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

if ( rpm_check( reference:"kernel-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-78.0.13.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
