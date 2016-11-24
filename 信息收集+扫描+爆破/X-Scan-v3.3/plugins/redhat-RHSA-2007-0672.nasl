
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25876);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0672:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0672");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix a number of security issues are now
  available for Red Hat Enterprise Linux 2.1 (32-bit architectures).

  This security advisory has been rated as having important security impact
  by
  the Red Hat Security Response Team.

  The Linux kernel handles the basic functions of the operating system.

  These new kernel packages contain fixes for the security issues described
  below:

  * a flaw in IPv6 flow label handling that allowed a local user to cause a
  denial of service (crash). (CVE-2007-1592, Important)

  * a flaw in the ISDN CAPI subsystem that allowed a remote user to cause a
  denial of service or potential privilege escalation. (CVE-2007-1217,
  Moderate)

  * a flaw in the Bluetooth subsystem that allowed a local user to trigger an
  information leak. (CVE-2007-1353, Low)

  * various flaws in the supported filesystems that allowed a local
  privileged user to cause a denial of service. (CVE-2006-6054,
  CVE-2006-6058,
  Low)

  Red Hat would like to thank Ilja van Sprundel for reporting an issue fixed
  in this erratum.

  All Red Hat Enterprise Linux 2.1 users are advised to upgrade their kernels
  to these updated packages, which contain backported fixes to correct these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0672.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6054", "CVE-2006-6058", "CVE-2007-1217", "CVE-2007-1353", "CVE-2007-1592");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.72.athlon.rpm               3c1762c99272c95caff4920b5c091600", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.72.athlon.rpm           248b4b045b45a51e3bdc7e6d5f032ab6", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.72", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
