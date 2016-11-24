
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40998);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1438: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1438");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and several bugs
  are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * the ADDR_COMPAT_LAYOUT and MMAP_PAGE_ZERO flags were not cleared when a
  setuid or setgid program was executed. A local, unprivileged user could use
  this flaw to bypass the mmap_min_addr protection mechanism and perform a
  NULL pointer dereference attack, or bypass the Address Space Layout
  Randomization (ASLR) security feature. (CVE-2009-1895, Important)

  * it was discovered that, when executing a new process, the clear_child_tid
  pointer in the Linux kernel is not cleared. If this pointer points to a
  writable portion of the memory of the new program, the kernel could corrupt
  four bytes of memory, possibly leading to a local denial of service or
  privilege escalation. (CVE-2009-2848, Important)

  * Solar Designer reported a missing capability check in the z90crypt driver
  in the Linux kernel. This missing check could allow a local user with an
  effective user ID (euid) of 0 to bypass intended capability restrictions.
  (CVE-2009-1883, Moderate)

  * a flaw was found in the way the do_sigaltstack() function in the Linux
  kernel copies the stack_t structure to user-space. On 64-bit machines, this
  flaw could lead to a four-byte information leak. (CVE-2009-2847, Moderate)

  This update also fixes the following bugs:

  * the gcc flag "-fno-delete-null-pointer-checks" was added to the kernel
  build options. This prevents gcc from optimizing out NULL pointer checks
  after the first use of a pointer. NULL pointer bugs are often exploited by
  attackers. Keeping these checks is a safety measure. (BZ#517964)

  * the Emulex LPFC driver has been updated to version 8.0.16.47, which
  fixes a memory leak that caused memory allocation failures and system
  hangs. (BZ#513192)

  * an error in the MPT Fusion driver makefile caused CSMI ioctls to not
  work with Serial Attached SCSI devices. (BZ#516184)

  * this update adds the mmap_min_addr tunable and restriction checks to help
  prevent unprivileged users from creating new memory mappings below the
  minimum address. This can help prevent the exploitation of NULL pointer
  deference bugs. Note that mmap_min_addr is set to zero (disabled) by
  default for backwards compatibility. (BZ#517904)

  * time-outs resulted in I/O errors being logged to "/var/log/messages" when
  running "mt erase" on tape drives using certain LSI MegaRAID SAS adapters,
  preventing the command from completing. The megaraid_sas driver\'s timeout
  value is now set to the OS layer value. (BZ#517965)

  * a locking issue caused the qla2xxx ioctl module to hang after
  encountering errors. This locking issue has been corrected. This ioctl
  module is used by the QLogic SAN management tools, such as SANsurfer and
  scli. (BZ#519428)

  * when a RAID 1 array that uses the mptscsi driver and the LSI 1030
  controller became degraded, the whole array was detected as being offline,
  which could cause kernel panics at boot or data loss. (BZ#517295)

  * on 32-bit architectures, if a file was held open and frequently written
  for more than 25 days, it was possible that the kernel would stop flushing
  those writes to storage. (BZ#515255)

  * a memory allocation bug in ib_mthca prevented the driver from loading if
  it was loaded with large values for the "num_mpt=" and "num_mtt=" options.
  (BZ#518707)

  * with this update, get_random_int() is more random and no longer uses a
  common seed value, reducing the possibility of predicting the values
  returned. (BZ#519692)

  * a bug in __ptrace_unlink() caused it to create deadlocked and unkillable
  processes. (BZ#519446)

  * previously, multiple threads using the fcntl() F_SETLK command to
  synchronize file access caused a deadlock in posix_locks_deadlock(). This
  could cause a system hang. (BZ#519429)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1438.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1883", "CVE-2009-1895", "CVE-2009-2847", "CVE-2009-2848");
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

if ( rpm_check( reference:"kernel-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.0.11.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.0.11.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
