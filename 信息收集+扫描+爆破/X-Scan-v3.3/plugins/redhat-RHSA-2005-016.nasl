
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16244);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-016:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-016");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in Red Hat
  Enterprise Linux 2.1 are now available.

  The Linux kernel handles the basic functions of the operating system.

  This advisory includes fixes for the following security issues:

  iSEC Security Research discovered a VMA handling flaw in the uselib(2)
  system call of the Linux kernel. A local user could make use of this
  flaw to gain elevated (root) privileges. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-1235 to
  this issue.

  iSEC Security Research discovered a flaw in the page fault handler code
  that could lead to local users gaining elevated (root) privileges on
  multiprocessor machines. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0001 to this issue.

  iSEC Security Research and Georgi Guninski independently discovered a flaw
  in the scm_send function in the auxiliary message layer. A local user
  could create a carefully crafted auxiliary message which could cause a
  denial of service (system hang). The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-1016 to this issue.

  Kirill Korotaev found a flaw in load_elf_binary affecting kernels prior to
  2.4.26. A local user could create a carefully crafted binary in such a
  way that it would cause a denial of service (system crash). The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  name CAN-2004-1234 to this issue.

  These packages also fix issues in the io_edgeport driver (CAN-2004-1017), a
  memory leak in ip_options_get (CAN-2004-1335), and missing VM_IO
  flags in some drivers (CAN-2004-1057).

  A recent Internet Draft by Fernando Gont recommended that ICMP Source
  Quench messages be ignored by hosts. A patch to ignore these messages is
  included.

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-016.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0791", "CVE-2004-1016", "CVE-2004-1017", "CVE-2004-1057", "CVE-2004-1234", "CVE-2004-1235", "CVE-2004-1335", "CVE-2005-0001");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.59.athlon.rpm               fa7d619b72c84b70323a2aab0cc4e4f4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.59.athlon.rpm           39ed572b73bcfe01e0dc02cd139737a0", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.59", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
