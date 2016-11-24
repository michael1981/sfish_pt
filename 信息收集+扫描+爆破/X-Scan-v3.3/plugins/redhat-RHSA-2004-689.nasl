
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16054);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-689:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-689");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in Red Hat
  Enterprise Linux 3 are now available.

  The Linux kernel handles the basic functions of the operating system.

  This advisory includes fixes for several security issues:

  Petr Vandrovec discovered a flaw in the 32bit emulation code affecting the
  Linux 2.4 kernel on the AMD64 architecture. A local attacker could use
  this flaw to gain privileges. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-1144 to this issue.

  ISEC security research discovered multiple vulnerabilities in the IGMP
  functionality which was backported in the Red Hat Enterprise Linux 3
  kernels. These flaws could allow a local user to cause a denial of
  service (crash) or potentially gain privileges. Where multicast
  applications are being used on a system, these flaws may also allow remote
  users to cause a denial of service. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-1137 to
  this issue.

  ISEC security research and Georgi Guninski independantly discovered a flaw
  in the scm_send function in the auxiliary message layer. A local user
  could create a carefully crafted auxiliary message which could cause a
  denial of service (system hang). The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-1016 to this issue.

  A floating point information leak was discovered in the ia64 architecture
  context switch code. A local user could use this flaw to read register
  values of other processes by setting the MFH bit. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  name CAN-2004-0565 to this issue.

  Kirill Korotaev found a flaw in load_elf_binary affecting kernels prior to
  2.4.26. A local user could create a carefully crafted binary in such a
  way that it would cause a denial of service (system crash). The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  name CAN-2004-1234 to this issue.

  These packages also fix issues in the io_edgeport driver, and a memory leak
  in ip_options_get.

  Note: The kernel-unsupported package contains various drivers and modules
  that are unsupported and therefore might contain security problems that
  have not been addressed.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-689.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0565", "CVE-2004-1016", "CVE-2004-1017", "CVE-2004-1137", "CVE-2004-1144", "CVE-2004-1234", "CVE-2004-1335");
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

if ( rpm_check( reference:"  kernel-2.4.21-27.0.1.EL.athlon.rpm                        1f8c7b25b7fffbc85993ec55905dcc5e", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-27.0.1.EL.athlon.rpm                    b7ec4b9732b8743940cab2f4853ccae8", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-27.0.1.EL.athlon.rpm        caec8b413e4b0bd3abe885fbde2b2d4c", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-27.0.1.EL.athlon.rpm            f67ab1ac2f5b06c9c0e97d074684974e", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-27.0.1.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
