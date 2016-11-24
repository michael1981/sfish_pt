
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22086);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2006-0437:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0437");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing support and
  maintenance of Red Hat Enterprise Linux version 3. This is the eighth
  regular update.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  This is the eighth regular kernel update to Red Hat Enterprise Linux 3.

  New features introduced by this update include:

  - addition of the adp94xx and dcdbas device drivers
  - diskdump support on megaraid_sas, qlogic, and swap partitions
  - support for new hardware via driver and SCSI white-list updates

  There were many bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement in
  the reliability and scalability of Red Hat Enterprise Linux 3.

  There were numerous driver updates and security fixes (elaborated below).
  Other key areas affected by fixes in this update include the networking
  subsystem, the NFS and autofs4 file systems, the SCSI and USB subsystems,
  and architecture-specific handling affecting AMD Opteron and Intel EM64T
  processors.

  The following device drivers have been added or upgraded to new versions:

  adp94xx -------- 1.0.8 (new)
  bnx2 ----------- 1.4.38
  cciss ---------- 2.4.60.RH1
  dcdbas --------- 5.6.0-1 (new)
  e1000 ---------- 7.0.33-k2
  emulex --------- 7.3.6
  forcedeth ------ 0.30
  ipmi ----------- 35.13
  qlogic --------- 7.07.04b6
  tg3 ------------ 3.52RH

  The following security bugs were fixed in this update:

  - a flaw in the USB devio handling of device removal that allowed a
  local user to cause a denial of service (crash) (CVE-2005-3055,
  moderate)

  - a flaw in the exec() handling of multi-threaded tasks using ptrace()
  that allowed a local user to cause a denial of service (hang of a
  user process) (CVE-2005-3107, low)

  - a difference in "sysretq" operation of EM64T (as opposed to Opteron)
  processors that allowed a local user to cause a denial of service
  (crash) upon return from certain system calls (CVE-2006-0741 and
  CVE-2006-0744, important)

  - a flaw in unaligned accesses handling on Intel Itanium processors
  that allowed a local user to cause a denial of service (crash)
  (CVE-2006-0742, important)

  - an info leak on AMD-based x86 and x86_64 systems that allowed a local
  user to retrieve the floating point exception state of a process
  run by a different user (CVE-2006-1056, important)

  - a flaw in IPv4 packet output handling that allowed a remote user to
  bypass the zero IP ID countermeasure on systems with a disabled
  firewall (CVE-2006-1242, low)

  - a minor info leak in socket option handling in the network code
  (CVE-2006-1343, low)

  - a flaw in IPv4 netfilter handling for the unlikely use of SNMP NAT
  processing that allowed a remote user to cause a denial of service
  (crash) or potential memory corruption (CVE-2006-2444, moderate)

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0437.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3055", "CVE-2005-3107", "CVE-2006-0741", "CVE-2006-0742", "CVE-2006-0744", "CVE-2006-1056", "CVE-2006-1242", "CVE-2006-1343", "CVE-2006-2444");
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

if ( rpm_check( reference:"  kernel-2.4.21-47.EL.athlon.rpm                        3a6be922eb8205b6e8890d524963fd12", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-47.EL.athlon.rpm                    6cb9e4f65d21ed49cd0b95a15b477c17", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-47.EL.athlon.rpm        f16baf3eacd80c5fd06b0fba15263089", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-47.EL.athlon.rpm            73778bab6685813ee7a10d84c62106e0", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-47.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
