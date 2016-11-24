
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42358);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1548: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1548");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix multiple security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * a system with SELinux enforced was more permissive in allowing local
  users in the unconfined_t domain to map low memory areas even if the
  mmap_min_addr restriction was enabled. This could aid in the local
  exploitation of NULL pointer dereference bugs. (CVE-2009-2695, Important)

  * a NULL pointer dereference flaw was found in the eCryptfs implementation
  in the Linux kernel. A local attacker could use this flaw to cause a local
  denial of service or escalate their privileges. (CVE-2009-2908, Important)

  * a flaw was found in the NFSv4 implementation. The kernel would do an
  unnecessary permission check after creating a file. This check would
  usually fail and leave the file with the permission bits set to random
  values. Note: This is a server-side only issue. (CVE-2009-3286, Important)

  * a NULL pointer dereference flaw was found in each of the following
  functions in the Linux kernel: pipe_read_open(), pipe_write_open(), and
  pipe_rdwr_open(). When the mutex lock is not held, the i_pipe pointer could
  be released by other processes before it is used to update the pipe\'s
  reader and writer counters. This could lead to a local denial of service or
  privilege escalation. (CVE-2009-3547, Important)

  * a flaw was found in the Realtek r8169 Ethernet driver in the Linux
  kernel. pci_unmap_single() presented a memory leak that could lead to IOMMU
  space exhaustion and a system crash. An attacker on the local network could
  abuse this flaw by using jumbo frames for large amounts of network traffic.
  (CVE-2009-3613, Important)

  * missing initialization flaws were found in the Linux kernel. Padding data
  in several core network structures was not initialized properly before
  being sent to user-space. These flaws could lead to information leaks.
  (CVE-2009-3228, Moderate)

  Bug fixes:

  * with network bonding in the "balance-tlb" or "balance-alb" mode, the
  primary setting for the primary slave device was lost when said device was
  brought down. Bringing the slave back up did not restore the primary
  setting. (BZ#517971)

  * some faulty serial device hardware caused systems running the kernel-xen
  kernel to take a very long time to boot. (BZ#524153)

  * a caching bug in nfs_readdir() may have caused NFS clients to see
  duplicate files or not see all files in a directory. (BZ#526960)

  * the RHSA-2009:1243 update removed the mpt_msi_enable option, preventing
  certain scripts from running. This update adds the option back. (BZ#526963)

  * an iptables rule with the recent module and a hit count value greater
  than the ip_pkt_list_tot parameter (the default is 20), did not have any
  effect over packets, as the hit count could not be reached. (BZ#527434)

  * a check has been added to the IPv4 code to make sure that rt is not NULL,
  to help prevent future bugs in functions that call ip_append_data() from
  being exploitable. (BZ#527436)

  * a kernel panic occurred in certain conditions after reconfiguring a tape
  drive\'s block size. (BZ#528133)

  * when using the Linux Virtual Server (LVS) in a master and backup
  configuration, and propagating active connections on the master to the
  backup, the connection timeout value on the backup was hard-coded to 180
  seconds, meaning connection information on the backup was soon lost. This
  could prevent the successful failover of connections. The timeout value
  can now be set via "ipvsadm --set". (BZ#528645)

  * a bug in nfs4_do_open_expired() could have caused the reclaimer thread on
  an NFSv4 client to enter an infinite loop. (BZ#529162)

  * MSI interrupts may not have been delivered for r8169 based network cards
  that have MSI interrupts enabled. This bug only affected certain systems.
  (BZ#529366)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1548.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2695", "CVE-2009-2908", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3613");
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

if ( rpm_check( reference:"kernel-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-164.6.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-164.6.1.el5", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
