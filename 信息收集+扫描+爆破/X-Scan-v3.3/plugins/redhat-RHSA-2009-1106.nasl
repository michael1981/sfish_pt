
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39430);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1106: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1106");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * several flaws were found in the way the Linux kernel CIFS implementation
  handles Unicode strings. CIFS clients convert Unicode strings sent by a
  server to their local character sets, and then write those strings into
  memory. If a malicious server sent a long enough string, it could write
  past the end of the target memory region and corrupt other memory areas,
  possibly leading to a denial of service or privilege escalation on the
  client mounting the CIFS share. (CVE-2009-1439, CVE-2009-1633, Important)

  * the Linux kernel Network File System daemon (nfsd) implementation did not
  drop the CAP_MKNOD capability when handling requests from local,
  unprivileged users. This flaw could possibly lead to an information leak or
  privilege escalation. (CVE-2009-1072, Moderate)

  * Frank Filz reported the NFSv4 client was missing a file permission check
  for the execute bit in some situations. This could allow local,
  unprivileged users to run non-executable files on NFSv4 mounted file
  systems. (CVE-2009-1630, Moderate)

  * a missing check was found in the hypervisor_callback() function in the
  Linux kernel provided by the kernel-xen package. This could cause a denial
  of service of a 32-bit guest if an application running in that guest
  accesses a certain memory location in the kernel. (CVE-2009-1758, Moderate)

  * a flaw was found in the AGPGART driver. The agp_generic_alloc_page() and
  agp_generic_alloc_pages() functions did not zero out the memory pages they
  allocate, which may later be available to user-space processes. This flaw
  could possibly lead to an information leak. (CVE-2009-1192, Low)

  Bug fixes:

  * a race in the NFS client between destroying cached access rights and
  unmounting an NFS file system could have caused a system crash. "Busy
  inodes" messages may have been logged. (BZ#498653)

  * nanosleep() could sleep several milliseconds less than the specified time
  on Intel Itanium®-based systems. (BZ#500349)

  * LEDs for disk drives in AHCI mode may have displayed a fault state when
  there were no faults. (BZ#500120)

  * ptrace_do_wait() reported tasks were stopped each time the process doing
  the trace called wait(), instead of reporting it once. (BZ#486945)

  * epoll_wait() may have caused a system lockup and problems for
  applications. (BZ#497322)

  * missing capabilities could possibly allow users with an fsuid other than
  0 to perform actions on some file system types that would otherwise be
  prevented. (BZ#497271)

  * on NFS mounted file systems, heavy write loads may have blocked
  nfs_getattr() for long periods, causing commands that use stat(2), such as
  ls, to hang. (BZ#486926)

  * in rare circumstances, if an application performed multiple O_DIRECT
  reads per virtual memory page and also performed fork(2), the buffer
  storing the result of the I/O may have ended up with invalid data.
  (BZ#486921)

  * when using GFS2, gfs2_quotad may have entered an uninterpretable sleep
  state. (BZ#501742)

  * with this update, get_random_int() is more random and no longer uses a
  common seed value, reducing the possibility of predicting the values
  returned. (BZ#499783)

  * the "-fwrapv" flag was added to the gcc build options to prevent gcc from
  optimizing away wrapping. (BZ#501751)

  * a kernel panic when enabling and disabling iSCSI paths. (BZ#502916)

  * using the Broadcom NetXtreme BCM5704 network device with the tg3 driver
  caused high system load and very bad performance. (BZ#502837)

  * "/proc/[pid]/maps" and "/proc/[pid]/smaps" can only be read by processes
  able to use the ptrace() call on a given process; however, certain
  information from "/proc/[pid]/stat" and "/proc/[pid]/wchan" could be used
  to reconstruct memory maps. (BZ#499546)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1106.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1072", "CVE-2009-1192", "CVE-2009-1439", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1758");
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

if ( rpm_check( reference:"kernel-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-128.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-128.1.14.el5", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
