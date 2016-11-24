
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19832);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-663:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-663");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing support and
  maintenance of Red Hat Enterprise Linux version 3. This is the sixth
  regular update.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the sixth regular kernel update to Red Hat Enterprise Linux 3.

  New features introduced by this update include:

  - diskdump support on HP Smart Array devices
  - netconsole/netdump support over bonded interfaces
  - new chipset and device support via PCI table updates
  - support for new "oom-kill" and "kscand_work_percent" sysctls
  - support for dual core processors and ACPI Power Management timers on
  AMD64 and Intel EM64T systems

  There were many bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement in
  the reliability and scalability of Red Hat Enterprise Linux 3.

  There were numerous driver updates and security fixes (elaborated below).
  Other key areas affected by fixes in this update include kswapd, inode
  handling, the SATA subsystem, diskdump handling, ptrace() syscall support,
  and signal handling.

  The following device drivers have been upgraded to new versions:

  3w-9xxx ---- 2.24.03.008RH
  cciss ------ 2.4.58.RH1
  e100 ------- 3.4.8-k2
  e1000 ------ 6.0.54-k2
  emulex ----- 7.3.2
  fusion ----- 2.06.16i.01
  iscsi ------ 3.6.2.1
  ipmi ------- 35.4
  lpfcdfc ---- 1.2.1
  qlogic ----- 7.05.00-RH1
  tg3 -------- 3.27RH

  The following security bugs were fixed in this update:

  - a flaw in syscall argument checking on Itanium systems that allowed
  a local user to cause a denial of service (crash) (CAN-2005-0136)

  - a flaw in stack expansion that allowed a local user of mlockall()
  to cause a denial of service (memory exhaustion) (CAN-2005-0179)

  - a small memory leak in network packet defragmenting that allowed a
  remote user to cause a denial of service (memory exhaustion) on
  systems using netfilter (CAN-2005-0210)

  - flaws in ptrace() syscall handling on AMD64 and Intel EM64T systems
  that allowed a local user to cause a denial of service (crash)
  (CAN-2005-0756, CAN-2005-1762, CAN-2005-2553)

  - flaws in ISO-9660 file system handling that allowed the mounting of
  an invalid image on a CD-ROM to cause a denial of service (crash)
  or potentially execute arbitrary code (CAN-2005-0815)

  - a flaw in ptrace() syscall handling on Itanium systems that allowed
  a local user to cause a denial of service (crash) (CAN-2005-1761)

  - a flaw in the alternate stack switching on AMD64 and Intel EM64T
  systems that allowed a local user to cause a denial of service
  (crash) (CAN-2005-1767)

  - race conditions in the ia32-compat support for exec() syscalls on
  AMD64, Intel EM64T, and Itanium systems that could allow a local
  user to cause a denial of service (crash) (CAN-2005-1768)

  - flaws in IPSEC network handling that allowed a local user to cause
  a denial of service or potentially gain privileges (CAN-2005-2456,
  CAN-2005-2555)

  - a flaw in sendmsg() syscall handling on 64-bit systems that allowed
  a local user to cause a denial of service or potentially gain
  privileges (CAN-2005-2490)

  - flaws in unsupported modules that allowed denial-of-service attacks
  (crashes) or local privilege escalations on systems using the drm,
  coda, or moxa modules (CAN-2004-1056, CAN-2005-0124, CAN-2005-0504)

  - potential leaks of kernel data from jfs and ext2 file system handling
  (CAN-2004-0181, CAN-2005-0400)

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-663.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0181", "CVE-2004-1056", "CVE-2005-0124", "CVE-2005-0136", "CVE-2005-0179", "CVE-2005-0210", "CVE-2005-0400", "CVE-2005-0504", "CVE-2005-0756", "CVE-2005-0815", "CVE-2005-1761", "CVE-2005-1762", "CVE-2005-1767", "CVE-2005-1768", "CVE-2005-2456", "CVE-2005-2490", "CVE-2005-2553", "CVE-2005-2555", "CVE-2005-3273", "CVE-2005-3274");
script_summary(english: "Check for the version of the   kernel packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"  kernel-2.4.21-37.EL.athlon.rpm                        24024fe9b3193481b6b21f867fcfc781", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-37.EL.athlon.rpm                    508cf0f34c04da1b911621aeb1070321", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-37.EL.athlon.rpm        1882c97258377bef50b9db0df4a5cf9f", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-37.EL.athlon.rpm            72e0653010d19e8ed68c6732f6e2b271", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-37.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
