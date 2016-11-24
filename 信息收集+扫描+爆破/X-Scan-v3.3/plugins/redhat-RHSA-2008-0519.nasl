
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33377);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0519: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0519");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix various security issues and a bug are now
  available for Red Hat Enterprise Linux 5.

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

  * Tavis Ormandy discovered a deficiency in the Linux kernel 32-bit and
  64-bit emulation. This could allow a local unprivileged user to prepare and
  run a specially crafted binary, which would use this deficiency to leak
  uninitialized and potentially sensitive data. (CVE-2008-0598, Important)

  * Brandon Edwards discovered a missing length validation check in the Linux
  kernel DCCP module reconciliation feature. This could allow a local
  unprivileged user to cause a heap overflow, gaining privileges for
  arbitrary code execution. (CVE-2008-2358, Moderate)

  As well, these updated packages fix the following bug:

  * Due to a regression, "gettimeofday" may have gone backwards on certain
  x86 hardware. This issue was quite dangerous for time-sensitive systems,
  such as those used for transaction systems and databases, and may have
  caused applications to produce incorrect results, or even crash.

  Red Hat Enterprise Linux 5 users are advised to upgrade to these updated
  packages, which contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0519.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0598", "CVE-2008-2358", "CVE-2008-2729");
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

if ( rpm_check( reference:"kernel-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-92.1.6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
