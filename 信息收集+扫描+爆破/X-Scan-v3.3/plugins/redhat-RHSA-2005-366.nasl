
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18095);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-366: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-366");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  [Updated 9 August 2005]
  The advisory text has been updated to show that this update fixed the
  security issue named CAN-2005-0210 but not CAN-2005-0209. The issue
  CAN-2005-0209 was actually fixed by RHSA-2005:420. No changes have been
  made to the packages associated with this advisory.

  The Linux kernel handles the basic functions of the operating system.

  A flaw in the fib_seq_start function was discovered. A local user could use
  this flaw to cause a denial of service (system crash) via /proc/net/route.
  (CAN-2005-1041)

  A flaw in the tmpfs file system was discovered. A local user could use this
  flaw to cause a denial of service (system crash). (CAN-2005-0977)

  An integer overflow flaw was found when writing to a sysfs file. A local
  user could use this flaw to overwrite kernel memory, causing a denial of
  service (system crash) or arbitrary code execution. (CAN-2005-0867)

  Keith Owens reported a flaw in the Itanium unw_unwind_to_user function. A
  local user could use this flaw to cause a denial of service (system crash)
  on Itanium architectures. (CAN-2005-0135)

  A flaw in the NFS client O_DIRECT error case handling was discovered. A
  local user could use this flaw to cause a denial of service (system crash).
  (CAN-2005-0207)

  A small memory leak when defragmenting local packets was discovered that
  affected the Linux 2.6 kernel netfilter subsystem. A local user could send
  a large number of carefully crafted fragments leading to memory exhaustion
  (CAN-2005-0210)

  A flaw was discovered in the Linux PPP driver. On systems allowing remote
  users to connect to a server using ppp, a remote client could cause a
  denial of service (system crash). (CAN-2005-0384)

  A flaw was discovered in the ext2 file system code. When a new directory is
  created, the ext2 block written to disk is not initialized, which could
  lead to an information leak if a disk image is made available to
  unprivileged users. (CAN-2005-0400)

  A flaw in fragment queuing was discovered that affected the Linux kernel
  netfilter subsystem. On systems configured to filter or process network
  packets (e.g. firewalling), a remote attacker could send a carefully
  crafted set of fragmented packets to a machine and cause a denial of
  service (system crash). In order to sucessfully exploit this flaw, the
  attacker would need to know or guess some aspects of the firewall ruleset
  on the target system. (CAN-2005-0449)

  A number of flaws were found in the Linux 2.6 kernel. A local user could
  use these flaws to read kernel memory or cause a denial of service (crash).
  (CAN-2005-0529, CAN-2005-0530, CAN-2005-0531)

  An integer overflow in sys_epoll_wait in eventpoll.c was discovered. A
  local user could use this flaw to overwrite low kernel memory. This memory
  is usually unused, not usually resulting in a security consequence.
  (CAN-2005-0736)

  A flaw when freeing a pointer in load_elf_library was discovered. A local
  user could potentially use this flaw to cause a denial of service (crash).
  (CAN-2005-0749)

  A flaw was discovered in the bluetooth driver system. On systems where the
  bluetooth modules are loaded, a local user could use this flaw to gain
  elevated (root) privileges. (CAN-2005-0750)

  A race condition was discovered that affected the Radeon DRI driver. A
  local user who has DRI privileges on a Radeon graphics card may be able to
  use this flaw to gain root privileges. (CAN-2005-0767)

  Multiple range checking flaws were discovered in the iso9660 file system
  handler. An attacker could create a malicious file system image which would
  cause a denial or service or potentially execute arbitrary code if mounted.
  (CAN-2005-0815)

  A flaw was discovered when setting line discipline on a serial tty. A local
  user may be able to use this flaw to inject mouse movements or keystrokes
  when another user is logged in. (CAN-2005-0839)

  Red Hat Enterprise Linux 4 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.

  Please note that


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-366.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0135", "CVE-2005-0207", "CVE-2005-0210", "CVE-2005-0384", "CVE-2005-0400", "CVE-2005-0449", "CVE-2005-0529", "CVE-2005-0530", "CVE-2005-0531", "CVE-2005-0736", "CVE-2005-0749", "CVE-2005-0750", "CVE-2005-0767", "CVE-2005-0815", "CVE-2005-0839", "CVE-2005-0867", "CVE-2005-0977", "CVE-2005-1041");
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

if ( rpm_check( reference:"kernel-2.6.9-5.0.5.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-5.0.5.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-5.0.5.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-5.0.5.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-5.0.5.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-5.0.5.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-5.0.5.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
