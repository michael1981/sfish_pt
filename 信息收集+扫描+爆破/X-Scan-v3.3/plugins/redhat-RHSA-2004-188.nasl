
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12494);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-188:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-188");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing
  support and maintenance of Red Hat Enterprise Linux version
  3. This is the second regular update.

  The Linux kernel handles the basic functions of the
  operating system.

  This is the second regular kernel update to Red Hat
  Enterprise Linux version 3. It contains several minor
  security fixes, many bug fixes, device driver updates,
  new hardware support, and the introduction of Linux
  Syscall Auditing support.

  There were bug fixes in many different parts of the kernel,
  the bulk of which addressed unusual situations such as error
  handling, race conditions, and resource starvation. The
  combined effect of the approximately 140 fixes is a strong
  improvement in the reliability and durability of Red Hat
  Enterprise Linux. Some of the key areas affected are disk
  drivers, network drivers, USB support, x86_64 and ppc64
  platform support, ia64 32-bit emulation layer enablers,
  and the VM, NFS, IPv6, and SCSI subsystems.

  A significant change in the SCSI subsystem (the disabling
  of the scsi-affine-queue patch) should significantly improve
  SCSI disk driver performance in many scenarios. There were
  10 Bugzillas against SCSI performance problems addressed
  by this change.

  The following drivers have been upgraded to new versions:

  bonding ---- 2.4.1
  cciss ------ 2.4.50.RH1
  e1000 ------ 5.2.30.1-k1
  fusion ----- 2.05.11.03
  ipr -------- 1.0.3
  ips -------- 6.11.07
  megaraid2 -- 2.10.1.1
  qla2x00 ---- 6.07.02-RH1
  tg3 -------- 3.1
  z90crypt --- 1.1.4

  This update introduces support for the new Intel EM64T
  processor. A new "ia32e" architecture has been created to
  support booting on platforms based on either the original
  AMD Opteron CPU or the new Intel EM64T CPU. The existing
  "x86_64" architecture has remained optimized for Opteron
  systems. Kernels for both types of systems are built from
  the same x86_64-architecture sources and share a common
  kernel source RPM (kernel-source-2.4.21-15.EL.x86_64.rpm).

  Other highlights in this update include a major upgrade to
  the SATA infrastructure, addition of IBM JS20 Power Blade
  support, and creation of an optional IBM eServer zSeries
  On-Demand Timer facility for reducing idle CPU overhead.

  The following security issues were addressed in this update:

  A minor flaw was found where /proc/tty/driver/serial reveals
  the exact character counts for serial links. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2003-0461 to this issue.

  The kernel strncpy() function in Linux 2.4 and 2.5 does not
  pad the target buffer with null bytes on architectures other
  than x86, as opposed to the expected libc behavior, which
  could lead to information leaks. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0465 to this issue.

  A minor data leak was found in two real time clock drivers
  (for /dev/rtc). The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name
  CAN-2003-0984 to this issue.

  A flaw in the R128 Direct Render Infrastructure (dri) driver
  could allow local privilege escalation. This driver is part
  of the kernel-unsupported package. The Common Vulnera-
  bilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0003 to this issue.

  A flaw in ncp_lookup() in ncpfs could allow local privilege
  escalation. The ncpfs module allows a system to mount
  volumes of NetWare servers or print to NetWare printers and
  is in the kernel-unsupported package. The Common Vulnera-
  bilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0010 to this issue.

  (Note that the kernel-unsupported package contains drivers
  and other modules that are unsupported and therefore might
  contain security problems that have not been addressed.)

  All Red Hat Enterprise Linux 3 users are advised to upgrade
  their kernels to the packages associated with their machine
  architectures and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-188.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0461", "CVE-2003-0465", "CVE-2003-0984", "CVE-2003-1040", "CVE-2004-0003", "CVE-2004-0010");
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

if ( rpm_check( reference:"  kernel-2.4.21-15.EL.athlon.rpm                        ccad3e4dbb561cca63badec7b6317163", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-15.EL.athlon.rpm                    2edfe3398e83c4dbb5ac47a9514a253f", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-15.EL.athlon.rpm        f6ff7ea30964f4960bb85e17cda3085e", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-15.EL.athlon.rpm            2740555623bc674229d0336ac9e10a84", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-15.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
