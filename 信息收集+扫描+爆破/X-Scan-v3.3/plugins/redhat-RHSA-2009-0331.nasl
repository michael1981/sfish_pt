
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35919);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2009-0331: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0331");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that resolve several security issues and fix
  various bugs are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update addresses the following security issues:

  * a buffer overflow was found in the Linux kernel Partial Reliable Stream
  Control Transmission Protocol (PR-SCTP) implementation. This could,
  potentially, lead to a denial of service if a Forward-TSN chunk is received
  with a large stream ID. (CVE-2009-0065, Important)

  * a memory leak was found in keyctl handling. A local, unprivileged user
  could use this flaw to deplete kernel memory, eventually leading to a
  denial of service. (CVE-2009-0031, Important)

  * a deficiency was found in the Remote BIOS Update (RBU) driver for Dell
  systems. This could allow a local, unprivileged user to cause a denial of
  service by reading zero bytes from the image_type or packet_size file in
  "/sys/devices/platform/dell_rbu/". (CVE-2009-0322, Important)

  * a deficiency was found in the libATA implementation. This could,
  potentially, lead to a denial of service. Note: by default, "/dev/sg*"
  devices are accessible only to the root user. (CVE-2008-5700, Low)

  This update also fixes the following bugs:

  * when the hypervisor changed a page table entry (pte) mapping from
  read-only to writable via a make_writable hypercall, accessing the changed
  page immediately following the change caused a spurious page fault. When
  trying to install a para-virtualized Red Hat Enterprise Linux 4 guest on a
  Red Hat Enterprise Linux 5.3 dom0 host, this fault crashed the installer
  with a kernel backtrace. With this update, the "spurious" page fault is
  handled properly. (BZ#483748)

  * net_rx_action could detect its cpu poll_list as non-empty, but have that
  same list reduced to empty by the poll_napi path. This resulted in garbage
  data being returned when net_rx_action calls list_entry, which subsequently
  resulted in several possible crash conditions. The race condition in the
  network code which caused this has been fixed. (BZ#475970, BZ#479681 &
  BZ#480741)

  * a misplaced memory barrier at unlock_buffer() could lead to a concurrent
  h_refcounter update which produced a reference counter leak and, later, a
  double free in ext3_xattr_release_block(). Consequent to the double free,
  ext3 reported an error

  ext3_free_blocks_sb: bit already cleared for block [block number]

  and mounted itself as read-only. With this update, the memory barrier is
  now placed before the buffer head lock bit, forcing the write order and
  preventing the double free. (BZ#476533)

  * when the iptables module was unloaded, it was assumed the correct entry
  for removal had been found if "wrapper->ops->pf" matched the value passed
  in by "reg->pf". If several ops ranges were registered against the same
  protocol family, however, (which was likely if you had both ip_conntrack
  and ip_contrack_* loaded) this assumption could lead to NULL list pointers
  and cause a kernel panic. With this update, "wrapper->ops" is matched to
  pointer values "reg", which ensures the correct entry is removed and
  results in no NULL list pointers. (BZ#477147)

  * when the pidmap page (used for tracking process ids, pids) incremented to
  an even page (ie the second, fourth, sixth, etc. pidmap page), the
  alloc_pidmap() routine skipped the page. This resulted in "holes" in the
  allocated pids. For example, after pid 32767, you would expect 32768 to be
  allocated. If the page skipping behavior presented, however, the pid
  allocated after 32767 was 65536. With this update, alloc_pidmap() no longer
  skips alternate pidmap pages and allocated pid holes no longer occur. This
  fix also corrects an error which allowed pid_max to be set higher than the
  pid_max limit has been corrected. (BZ#479182)

  All Red Hat Enterprise Linux 4 users should upgrade to these updated
  packages, which contain backported patches to resolve these issues. The
  system must be rebooted for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0331.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-5700", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0322");
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

if ( rpm_check( reference:"kernel-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-78.0.17.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
