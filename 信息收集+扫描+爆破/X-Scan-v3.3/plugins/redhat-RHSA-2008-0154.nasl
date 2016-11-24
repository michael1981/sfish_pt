
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31388);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0154: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0154");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * a flaw in the hypervisor for hosts running on Itanium architectures
  allowed an Intel VTi domain to read arbitrary physical memory from other
  Intel VTi domains, which could make information available to unauthorized
  users. (CVE-2007-6207, Important)

  * two buffer overflow flaws were found in ISDN subsystem. A local
  unprivileged user could use these flaws to cause a denial of service.
  (CVE-2007-5938: Important, CVE-2007-6063: Moderate)

  * a possible NULL pointer dereference was found in the subsystem used for
  showing CPU information, as used by CHRP systems on PowerPC architectures.
  This may have allowed a local unprivileged user to cause a denial of
  service (crash). (CVE-2007-6694, Moderate)

  * a flaw was found in the handling of zombie processes. A local user could
  create processes that would not be properly reaped, possibly causing a
  denial of service. (CVE-2006-6921, Moderate)

  As well, these updated packages fix the following bugs:

  * a bug was found in the Linux kernel audit subsystem. When the audit
  daemon was setup to log the execve system call with a large number of
  arguments, the kernel could run out of memory, causing a kernel panic.

  * on IBM System z architectures, using the IBM Hardware Management Console
  to toggle IBM FICON channel path ids (CHPID) caused a file ID miscompare,
  possibly causing data corruption.

  * when running the IA-32 Execution Layer (IA-32EL) or a Java VM on Itanium
  architectures, a bug in the address translation in the hypervisor caused
  the wrong address to be registered, causing Dom0 to hang.

  * on Itanium architectures, frequent Corrected Platform Error errors may
  have caused the hypervisor to hang.

  * when enabling a CPU without hot plug support, routines for checking the
  presence of the CPU were missing. The CPU tried to access its own
  resources, causing a kernel panic.

  * after updating to kernel-2.6.18-53.el5, a bug in the CCISS driver caused
  the HP Array Configuration Utility CLI to become unstable, possibly causing
  a system hang, or a kernel panic.

  * a bug in NFS directory caching could have caused different hosts to have
  different views of NFS directories.

  * on Itanium architectures, the Corrected Machine Check Interrupt masked
  hot-added CPUs as disabled.

  * when running Oracle database software on the Intel 64 and AMD64
  architectures, if an SGA larger than 4GB was created, and had hugepages
  allocated to it, the hugepages were not freed after database shutdown.

  * in a clustered environment, when two or more NFS clients had the same
  logical volume mounted, and one of them modified a file on the volume, NULL
  characters may have been inserted, possibly causing data corruption.

  These updated packages resolve several severe issues in the lpfc driver:

  * a system hang after LUN discovery.

  * a general fault protection, a NULL pointer dereference, or slab
  corruption could occur while running a debug on the kernel.

  * the inability to handle kernel paging requests in "lpfc_get_scsi_buf".

  * erroneous structure references caused certain FC discovery routines to
  reference and change "lpfc_nodelist" structures, even after they were
  freed.

  * the lpfc driver failed to interpret certain fields correctly, causing
  tape backup software to fail. Tape drives reported "Illegal Request".

  * the lpfc driver did not clear structures correctly, resulting in SCSI
  I/Os being rejected by targets, and causing errors.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0154.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6921", "CVE-2007-5938", "CVE-2007-6063", "CVE-2007-6207", "CVE-2007-6694");
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

if ( rpm_check( reference:"kernel-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-53.1.14.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
