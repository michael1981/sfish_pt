
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39583);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1132: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1132");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and various bugs
  are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * a flaw was found in the Intel PRO/1000 network driver in the Linux
  kernel. Frames with sizes near the MTU of an interface may be split across
  multiple hardware receive descriptors. Receipt of such a frame could leak
  through a validation check, leading to a corruption of the length check. A
  remote attacker could use this flaw to send a specially-crafted packet that
  would cause a denial of service. (CVE-2009-1385, Important)

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

  These updated packages also fix the following bugs:

  * "/proc/[pid]/maps" and "/proc/[pid]/smaps" can only be read by processes
  able to use the ptrace() call on a given process; however, certain
  information from "/proc/[pid]/stat" and "/proc/[pid]/wchan" could be used
  to reconstruct memory maps, making it possible to bypass the Address Space
  Layout Randomization (ASLR) security feature. This update addresses this
  issue. (BZ#499549)

  * in some situations, the link count was not decreased when renaming unused
  files on NFS mounted file systems. This may have resulted in poor
  performance. With this update, the link count is decreased in these
  situations, the same as is done for other file operations, such as unlink
  and rmdir. (BZ#501802)

  * tcp_ack() cleared the probes_out variable even if there were outstanding
  packets. When low TCP keepalive intervals were used, this bug may have
  caused problems, such as connections terminating, when using remote tools
  such as rsh and rlogin. (BZ#501754)

  * off-by-one errors in the time normalization code could have caused
  clock_gettime() to return one billion nanoseconds, rather than adding an
  extra second. This bug could have caused the name service cache daemon
  (nscd) to consume excessive CPU resources. (BZ#501800)

  * a system panic could occur when one thread read "/proc/bus/input/devices"
  while another was removing a device. With this update, a mutex has been
  added to protect the input_dev_list and input_handler_list variables, which
  resolves this issue. (BZ#501804)

  * using netdump may have caused a kernel deadlock on some systems.
  (BZ#504565)

  * the file system mask, which lists capabilities for users with a file
  system user ID (fsuid) of 0, was missing the CAP_MKNOD and
  CAP_LINUX_IMMUTABLE capabilities. This could, potentially, allow users with
  an fsuid other than 0 to perform actions on some file system types that
  would otherwise be prevented. This update adds these capabilities. (BZ#497269)

  All Red Hat Enterprise Linux 4 users should upgrade to these updated
  packages, which contain backported patches to resolve these issues. Note:
  The system must be rebooted for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1132.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1072", "CVE-2009-1192", "CVE-2009-1385", "CVE-2009-1630", "CVE-2009-1758");
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

if ( rpm_check( reference:"kernel-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.0.3.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-89.0.3.EL", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
