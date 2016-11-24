
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18313);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-294:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-294");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing support
  and maintenance of Red Hat Enterprise Linux version 3. This is the
  fifth regular update.

  The Linux kernel handles the basic functions of the operating system.

  This is the fifth regular kernel update to Red Hat Enterprise Linux 3.

  New features introduced by this update include:

  - support for 2-TB partitions on block devices
  - support for new disk, network, and USB devices
  - support for clustered APIC mode on AMD64 NUMA systems
  - netdump support on AMD64, Intel EM64T, Itanium, and ppc64 systems
  - diskdump support on sym53c8xx and SATA piix/promise adapters
  - NMI switch support on AMD64 and Intel EM64T systems

  There were many bug fixes in various parts of the kernel. The ongoing
  effort to resolve these problems has resulted in a marked improvement
  in the reliability and scalability of Red Hat Enterprise Linux 3.

  Some key areas affected by these fixes include the kernel\'s networking,
  SATA, TTY, and USB subsystems, as well as the architecture-dependent
  handling under the ia64, ppc64, and x86_64 directories. Scalability
  improvements were made primarily in the memory management and file
  system areas.

  A flaw in offset handling in the xattr file system code backported to
  Red Hat Enterprise Linux 3 was fixed. On 64-bit systems, a user who
  can access an ext3 extended-attribute-enabled file system could cause
  a denial of service (system crash). This issue is rated as having a
  moderate security impact (CAN-2005-0757).

  The following device drivers have been upgraded to new versions:

  3c59x ------ LK1.1.18
  3w-9xxx ---- 2.24.00.011fw (new in Update 5)
  3w-xxxx ---- 1.02.00.037
  8139too ---- (upstream 2.4.29)
  b44 -------- 0.95
  cciss ------ v2.4.54.RH1
  e100 ------- 3.3.6-k2
  e1000 ------ 5.6.10.1-k2
  lpfcdfc ---- 1.0.13 (new in Update 5)
  tg3 -------- 3.22RH

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-294.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0757");
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

if ( rpm_check( reference:"  kernel-2.4.21-32.EL.athlon.rpm                        8992dd4ed1397d860a1ae85dfc7b2dbd", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-32.EL.athlon.rpm                    5d86be94c356e79de1ed971fa4a0ac75", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-32.EL.athlon.rpm        55fd4b598560907990a420ce99932f57", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-32.EL.athlon.rpm            6110eda2670195aacb0bac8f8e378d33", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-32.EL", release:'RHEL3') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
