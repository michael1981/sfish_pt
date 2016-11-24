
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15958);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-505:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-505");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available as part of ongoing
  support and maintenance of Red Hat Enterprise Linux version
  2.1. This is the sixth regular update.

  The Linux kernel handles the basic functions of the operating
  system.

  This is the sixth regular kernel update to Red Hat Enterprise Linux version
  2.1. It updates a number of device drivers, and adds much improved SATA
  support.

  This update includes fixes for several security issues:

  Paul Starzetz of iSEC discovered various flaws in the ELF binary
  loader affecting kernels prior to 2.4.28. A local user could use these
  flaws to gain read access to executable-only binaries or possibly gain
  privileges. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CAN-2004-1070, CAN-2004-1071,
  CAN-2004-1072, and CAN-2004-1073 to these issues.

  A missing serialization flaw in unix_dgram_recvmsg was discovered that
  affects kernels prior to 2.4.28. A local user could potentially make
  use of a race condition in order to gain privileges. (CAN-2004-1068)

  Stefan Esser discovered various flaws including buffer overflows in
  the smbfs driver affecting kernels before 2.4.28. A local user may be
  able to cause a denial of service (crash) or possibly gain privileges.
  In order to exploit these flaws the user would need to have control of
  a connected smb server. (CAN-2004-0883, CAN-2004-0949)

  Conectiva discovered flaws in certain USB drivers affecting kernels
  before 2.4.27 which used the copy_to_user function on uninitialized
  structures. These flaws could allow local users to read small
  amounts of kernel memory. (CAN-2004-0685)

  The ext3 code in kernels before 2.4.26 did not properly initialize journal
  descriptor blocks. A privileged local user could read portions of kernel
  memory. (CAN-2004-0177)

  The following drivers have also been updated:

  * tg3 v3.10
  * e1000 v5.3.19-k2
  * e100 v3.0.27-k2
  * megaraid
  * megaraid2 v2.10.8.2

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-505.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0177", "CVE-2004-0685", "CVE-2004-0883", "CVE-2004-0949", "CVE-2004-1068", "CVE-2004-1070", "CVE-2004-1071", "CVE-2004-1072", "CVE-2004-1073");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.57.athlon.rpm               774ca4f6c93f8f8d068f226514c67c32", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.57.athlon.rpm           1cfb20abe116a544e50438205c26bb8a", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.57", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
