
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33376);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0508: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0508");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues and a bug are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * A security flaw was found in the Linux kernel memory copy routines, when
  running on certain AMD64 systems. If an unsuccessful attempt to copy kernel
  memory from source to destination memory locations occurred, the copy
  routines did not zero the content at the destination memory location. This
  could allow a local unprivileged user to view potentially sensitive data.
  (CVE-2008-2729, Important)

  * Alexey Dobriyan discovered a race condition in the Linux kernel
  process-tracing system call, ptrace. A local unprivileged user could
  use this flaw to cause a denial of service (kernel hang).
  (CVE-2008-2365, Important)

  * Tavis Ormandy discovered a deficiency in the Linux kernel 32-bit and
  64-bit emulation. This could allow a local unprivileged user to prepare and
  run a specially crafted binary, which would use this deficiency to leak
  uninitialized and potentially sensitive data. (CVE-2008-0598, Important)

  * It was discovered that the Linux kernel handled string operations in the
  opposite way to the GNU Compiler Collection (GCC). This could allow a local
  unprivileged user to cause memory corruption. (CVE-2008-1367, Low)

  As well, these updated packages fix the following bug:

  * On systems with a large number of CPUs (more than 16), multiple
  applications calling the "times()" system call may have caused a system
  hang.

  Red Hat Enterprise Linux 4 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0508.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0598", "CVE-2008-1367", "CVE-2008-2365", "CVE-2008-2729");
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

if ( rpm_check( reference:"kernel-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-devel-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-devel-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xenU-devel-2.6.9-67.0.20.EL", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
