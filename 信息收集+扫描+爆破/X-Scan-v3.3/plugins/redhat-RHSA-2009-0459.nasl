
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38661);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-0459: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0459");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and various bugs
  are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * a logic error was found in the do_setlk() function of the Linux kernel
  Network File System (NFS) implementation. If a signal interrupted a lock
  request, the local POSIX lock was incorrectly created. This could cause a
  denial of service on the NFS server if a file descriptor was closed before
  its corresponding lock request returned. (CVE-2008-4307, Important)

  * a deficiency was found in the Linux kernel system call auditing
  implementation on 64-bit systems. This could allow a local, unprivileged
  user to circumvent a system call audit configuration, if that configuration
  filtered based on the "syscall" number or arguments.
  (CVE-2009-0834, Important)

  * Chris Evans reported a deficiency in the Linux kernel signals
  implementation. The clone() system call permits the caller to indicate the
  signal it wants to receive when its child exits. When clone() is called
  with the CLONE_PARENT flag, it permits the caller to clone a new child that
  shares the same parent as itself, enabling the indicated signal to be sent
  to the caller\'s parent (instead of the caller), even if the caller\'s parent
  has different real and effective user IDs. This could lead to a denial of
  service of the parent. (CVE-2009-0028, Moderate)

  * the sock_getsockopt() function in the Linux kernel did not properly
  initialize a data structure that can be directly returned to user-space
  when the getsockopt() function is called with SO_BSDCOMPAT optname set.
  This flaw could possibly lead to memory disclosure.
  (CVE-2009-0676, Moderate)

  Bug fixes:

  * a kernel crash may have occurred for Red Hat Enterprise Linux 4.7 guests
  if their guest configuration file specified "vif = [ "type=ioemu" ]". This
  crash only occurred when starting guests via the "xm create" command.
  (BZ#477146)

  * a bug in IO-APIC NMI watchdog may have prevented Red Hat Enterprise Linux
  4.7 from being installed on HP ProLiant DL580 G5 systems. Hangs during
  installation and "NMI received for unknown reason [xx]" errors may have
  occurred. (BZ#479184)

  * a kernel deadlock on some systems when using netdump through a network
  interface that uses the igb driver. (BZ#480579)

  * a possible kernel hang in sys_ptrace() on the Itanium® architecture,
  possibly triggered by tracing a threaded process with strace. (BZ#484904)

  * the RHSA-2008:0665 errata only fixed the known problem with the LSI Logic
  LSI53C1030 Ultra320 SCSI controller, for tape devices. Read commands sent
  to tape devices may have received incorrect data. This issue may have led
  to data corruption. This update includes a fix for all types of devices.
  (BZ#487399)

  * a missing memory barrier caused a race condition in the AIO subsystem
  between the read_events() and aio_complete() functions. This may have
  caused a thread in read_events() to sleep indefinitely, possibly causing an
  application hang. (BZ#489935)

  * due to a lack of synchronization in the NFS client code, modifications
  to some pages (for files on an NFS mounted file system) made through a
  region of memory mapped by mmap() may be lost if the NFS client invalidates
  its page cache for particular files. (BZ#490119)

  * a NULL pointer dereference in the megaraid_mbox driver caused a system
  crash on some systems. (BZ#493420)

  * the ext3_symlink() function in the ext3 file system code used an
  illegal __GFP_FS allocation inside some transactions. This may have
  resulted in a kernel panic and "Assertion failure" errors. (BZ#493422)

  * do_machine_check() cleared all Machine Check Exception (MCE) status
  registers, preventing the BIOS from using them to determine the cause of
  certain panics and errors. (BZ#494915)

  * a bug prevented NMI watchdog from initializing on HP ProLiant DL580 G5
  systems. (BZ#497330)

  This update contains backported patches to fix these issues. The system
  must be rebooted for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0459.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4307", "CVE-2009-0028", "CVE-2009-0676", "CVE-2009-0834");
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

if ( rpm_check( reference:"kernel-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-78.0.22.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
