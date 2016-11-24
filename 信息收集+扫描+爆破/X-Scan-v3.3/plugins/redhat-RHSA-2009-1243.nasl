
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40835);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1243: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1243");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix security issues, address several hundred
  bugs and add numerous enhancements are now available as part of the ongoing
  support and maintenance of Red Hat Enterprise Linux version 5. This is the
  fourth regular update.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * it was discovered that, when executing a new process, the clear_child_tid
  pointer in the Linux kernel is not cleared. If this pointer points to a
  writable portion of the memory of the new program, the kernel could corrupt
  four bytes of memory, possibly leading to a local denial of service or
  privilege escalation. (CVE-2009-2848, Important)

  * a flaw was found in the way the do_sigaltstack() function in the Linux
  kernel copies the stack_t structure to user-space. On 64-bit machines, this
  flaw could lead to a four-byte information leak. (CVE-2009-2847, Moderate)

  * a flaw was found in the ext4 file system code. A local attacker could use
  this flaw to cause a denial of service by performing a resize operation on
  a specially-crafted ext4 file system. (CVE-2009-0745, Low)

  * multiple flaws were found in the ext4 file system code. A local attacker
  could use these flaws to cause a denial of service by mounting a
  specially-crafted ext4 file system. (CVE-2009-0746, CVE-2009-0747,
  CVE-2009-0748, Low)

  These updated packages also include several hundred bug fixes for and
  enhancements to the Linux kernel. Space precludes documenting each of these
  changes in this advisory and users are directed to the Red Hat Enterprise
  Linux 5.4 Release Notes for information on the most significant of these
  changes:

  http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5.4/html/
  Release_Notes/

  Also, for details concerning every bug fixed in and every enhancement added
  to the kernel for this release, see the kernel chapter in the Red Hat
  Enterprise Linux 5.4 Technical Notes:

  http://www.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5.4/html/
  Technical_Notes/kernel.html

  All Red Hat Enterprise Linux 5 users are advised to install these updated
  packages, which address these vulnerabilities as well as fixing the bugs
  and adding the enhancements noted in the Red Hat Enterprise Linux 5.4
  Release Notes and Technical Notes. The system must be rebooted for this
  update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1243.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748", "CVE-2009-2847", "CVE-2009-2848");
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

if ( rpm_check( reference:"kernel-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-PAE-devel-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-devel-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-devel-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-xen-devel-2.6.18-164.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
