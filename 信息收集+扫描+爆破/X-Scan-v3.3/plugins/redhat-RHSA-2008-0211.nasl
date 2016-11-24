
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32160);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2008-0211:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0211");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and several bugs
  are now available for Red Hat Enterprise Linux 3.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * the absence of a protection mechanism when attempting to access a
  critical section of code has been found in the Linux kernel open file
  descriptors control mechanism, fcntl. This could allow a local unprivileged
  user to simultaneously execute code, which would otherwise be protected
  against parallel execution. As well, a race condition when handling locks
  in the Linux kernel fcntl functionality, may have allowed a process
  belonging to a local unprivileged user to gain re-ordered access to the
  descriptor table. (CVE-2008-1669, Important)

  * the absence of a protection mechanism when attempting to access a
  critical section of code, as well as a race condition, have been found in
  the Linux kernel file system event notifier, dnotify. This could allow a
  local unprivileged user to get inconsistent data, or to send arbitrary
  signals to arbitrary system processes. (CVE-2008-1375, Important)

  Red Hat would like to thank Nick Piggin for responsibly disclosing the
  following issue:

  * when accessing kernel memory locations, certain Linux kernel drivers
  registering a fault handler did not perform required range checks. A local
  unprivileged user could use this flaw to gain read or write access to
  arbitrary kernel memory, or possibly cause a kernel crash.
  (CVE-2008-0007, Important)

  * a flaw was found when performing asynchronous input or output operations
  on a FIFO special file. A local unprivileged user could use this flaw to
  cause a kernel panic. (CVE-2007-5001, Important)

  * a flaw was found in the way core dump files were created. If a local user
  could get a root-owned process to dump a core file into a directory, which
  the user has write access to, they could gain read access to that core
  file. This could potentially grant unauthorized access to sensitive
  information. (CVE-2007-6206, Moderate)

  * a buffer overflow was found in the Linux kernel ISDN subsystem. A local
  unprivileged user could use this flaw to cause a denial of service.
  (CVE-2007-6151, Moderate)

  * a race condition found in the mincore system core could allow a local
  user to cause a denial of service (system hang). (CVE-2006-4814, Moderate)

  * it was discovered that the Linux kernel handled string operations in the
  opposite way to the GNU Compiler Collection (GCC). This could allow a local
  unprivileged user to cause memory corruption. (CVE-2008-1367, Low)

  As well, these updated packages fix the following bugs:

  * a bug, which caused long delays when unmounting mounts containing a large
  number of unused dentries, has been resolved.

  * in the previous kernel packages, the kernel was unable to handle certain
  floating point instructions on Itanium(R) architectures.

  * on certain Intel CPUs, the Translation Lookaside Buffer (TLB) was not
  flushed correctly, which caused machine check errors.

  Red Hat Enterprise Linux 3 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0211.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-4814", "CVE-2007-5001", "CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0007", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1669");
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

if ( rpm_check( reference:"  kernel-2.4.21-57.EL.athlon.rpm                        30d34f35a519d3822ee8c50c42f18610", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-57.EL.athlon.rpm                    82791fcb78478942b38e27bf13f54f9b", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-57.EL.athlon.rpm        ba14428901f6388e7324b5392e2e10e8", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-57.EL.athlon.rpm            3a4ccef29b3a9f6f58ffe6e1739fde31", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-57.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
