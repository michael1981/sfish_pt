
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(22054);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0579:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0579");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix a number of security issues as well as
  other bugs are now available for Red Hat Enterprise Linux 2.1 (32 bit
  architectures)

  This security advisory has been rated as having important security impact
  by the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues described
  below:

  * a flaw in the USB devio handling of device removal that allowed a local
  user to cause a denial of service (crash) (CVE-2005-3055, moderate)

  * a flaw in ROSE due to missing verification of the ndigis argument of new
  routes (CVE-2005-3273, moderate)

  * an info leak on AMD-based x86 systems that allowed a local user to
  retrieve the floating point exception state of a process run by a different
  user (CVE-2006-1056, important)

  * a minor info leak in socket name handling in the network code
  (CVE-2006-1342, low)

  * a minor info leak in socket option handling in the network code
  (CVE-2006-1343, low)

  * a directory traversal vulnerability in smbfs that allowed a local user to
  escape chroot restrictions for an SMB-mounted filesystem via "..\\\\"
  sequences (CVE-2006-1864, moderate)

  * a flaw in the mprotect system call that allowed to give write permission
  to a readonly attachment of shared memory (CVE-2006-2071, moderate)

  A performance bug in the NFS implementation that caused clients to
  frequently pause when sending TCP segments during heavy write loads was
  also addressed.

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels
  to these updated packages, which contain backported fixes to correct these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0579.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3055", "CVE-2005-3273", "CVE-2006-1056", "CVE-2006-1342", "CVE-2006-1343", "CVE-2006-1864", "CVE-2006-2071");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.70.athlon.rpm               a01f8a420613698289df25b15b37c347", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.70.athlon.rpm           909da40944a1664786e7881119735cad", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.70", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
