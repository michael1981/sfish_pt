
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22918);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0710:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0710");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in the Red Hat
  Enterprise Linux 3 kernel are now available.

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues described
  below:

  * a flaw in the IPC shared-memory implementation that allowed a local user
  to cause a denial of service (deadlock) that resulted in freezing the
  system (CVE-2006-4342, Important)

  * an information leak in the copy_from_user() implementation on s390 and
  s390x platforms that allowed a local user to read arbitrary kernel memory
  (CVE-2006-5174, Important)

  * a flaw in the ATM subsystem affecting systems with installed ATM
  hardware and configured ATM support that allowed a remote user to cause
  a denial of service (panic) by accessing socket buffer memory after it
  has been freed (CVE-2006-4997, Moderate)

  * a directory traversal vulnerability in smbfs that allowed a local user
  to escape chroot restrictions for an SMB-mounted filesystem via "..\\\\"
  sequences (CVE-2006-1864, Moderate)

  * a flaw in the mprotect system call that allowed enabling write permission
  for a read-only attachment of shared memory (CVE-2006-2071, Moderate)

  * a flaw in the DVD handling of the CDROM driver that could be used
  together with a custom built USB device to gain root privileges
  (CVE-2006-2935, Moderate)

  In addition to the security issues described above, a bug fix for a clock
  skew problem (which could lead to unintended keyboard repeat under X11)
  was also included. The problem only occurred when running the 32-bit x86
  kernel on 64-bit dual-core x86_64 hardware.

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their kernels
  to the packages associated with their machine architecture and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0710.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-1864", "CVE-2006-2071", "CVE-2006-2935", "CVE-2006-4342", "CVE-2006-4997", "CVE-2006-5174");
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

if ( rpm_check( reference:"  kernel-2.4.21-47.0.1.EL.athlon.rpm                        0f313988a3b5ee1c13eef6ac33f90366", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-47.0.1.EL.athlon.rpm                    51ae45ba954b3ff40f4f162c369fefbe", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-47.0.1.EL.athlon.rpm        91abcffc492b21a8953a2745ddbed3e2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-47.0.1.EL.athlon.rpm            b0c04546c3d59e4d6646123d41ecdc35", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-47.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
