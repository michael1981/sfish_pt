
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12451);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-017:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-017");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing
  support and maintenance of Red Hat Enterprise Linux version
  3. This is the first regular update.

  The Linux kernel handles the basic functions of the operating
  system.

  This is the first regular kernel update for Red Hat Enterprise
  Linux version 3. It contains a new critical security fix, many
  other bug fixes, several device driver updates, and numerous
  performance and scalability enhancements.

  On AMD64 systems, a fix was made to the eflags checking in
  32-bit ptrace emulation that could have allowed local users
  to elevate their privileges. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0001 to this issue.

  Other bug fixes were made in the following kernel areas:
  VM, NPTL, IPC, kernel timer, ext3, NFS, netdump, SCSI,
  ACPI, several device drivers, and machine-dependent
  support for the x86_64, ppc64, and s390 architectures.

  The VM subsystem was improved to better handle extreme
  loads and resource contention (such as might occur during
  heavy database application usage). This has resulted in
  a significantly reduced possibility of hangs, OOM kills,
  and low-mem exhaustion.

  Several NPTL fixes were made to resolve POSIX compliance
  issues concerning process IDs and thread IDs. A section
  in the Release Notes elaborates on a related issue with
  file record locking in multi-threaded applications.

  AMD64 kernels are now configured with NUMA support,
  S390 kernels now have CONFIG_BLK_STATS enabled, and
  DMA capability was restored in the IA64 agpgart driver.

  The following drivers have been upgraded to new versions:

  cmpci ------ 6.36
  e100 ------- 2.3.30-k1
  e1000 ------ 5.2.20-k1
  ips -------- 6.10.52
  megaraid --- v1.18k
  megaraid2 -- v2.00.9

  All Red Hat Enterprise Linux 3 users are advised to upgrade
  their kernels to the packages associated with their machine
  architectures and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-017.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0986", "CVE-2004-0001");
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

if ( rpm_check( reference:"  kernel-2.4.21-9.EL.athlon.rpm                        ed1284363a046a45ae4f59fbe43def3f", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-9.EL.athlon.rpm                    bef88e6becebe943da7a21ff4dad573e", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-9.EL.athlon.rpm        d75b6a19ff691700e82db24d5c6c8b45", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-9.EL.athlon.rpm            b39a4c74e306ab4a27e2d7c60df4b513", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-9.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
