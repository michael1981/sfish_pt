
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16211);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-043:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-043");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in Red Hat
  Enterprise Linux 3 are now available.

  The Linux kernel handles the basic functions of the operating system.

  This advisory includes fixes for several security issues:

  iSEC Security Research discovered a VMA handling flaw in the uselib(2)
  system call of the Linux kernel. A local user could make use of this
  flaw to gain elevated (root) privileges. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-1235 to
  this issue.

  A flaw was discovered where an executable could cause a VMA overlap leading
  to a crash. A local user could trigger this flaw by creating a carefully
  crafted a.out binary on 32-bit systems or a carefully crafted ELF binary
  on Itanium systems. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0003 to this issue.

  iSEC Security Research discovered a flaw in the page fault handler code
  that could lead to local users gaining elevated (root) privileges on
  multiprocessor machines. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0001 to this issue. A patch
  that coincidentally fixed this issue was committed to the Update 4 kernel
  release in December 2004. Therefore Red Hat Enterprise Linux 3 kernels
  provided by RHBA-2004:550 and subsequent updates are not vulnerable to
  this issue.

  A flaw in the system call filtering code in the audit subsystem included
  in Red Hat Enterprise Linux 3 allowed a local user to cause a crash when
  auditing was enabled. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-1237 to this issue.

  Olaf Kirch discovered that the recent security fixes for cmsg_len handling
  (CAN-2004-1016) broke 32-bit compatibility on 64-bit platforms such as
  AMD64 and Intel EM64T. A patch to correct this issue is included.

  A recent Internet Draft by Fernando Gont recommended that ICMP Source
  Quench messages be ignored by hosts. A patch to ignore these messages is
  included.

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-043.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0791", "CVE-2004-1074", "CVE-2004-1235", "CVE-2004-1237", "CVE-2005-0003");
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

if ( rpm_check( reference:"  kernel-2.4.21-27.0.2.EL.athlon.rpm                        8d10a00490ab122236ab19b7c37c2b84", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-27.0.2.EL.athlon.rpm                    ea13d1cd096d82f86ac94954666ba4e7", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-27.0.2.EL.athlon.rpm        fb2768b0daea74a8e281a0379da9acec", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-27.0.2.EL.athlon.rpm            030e4934b0f5b2a3468a75c997026e0d", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-27.0.2.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
