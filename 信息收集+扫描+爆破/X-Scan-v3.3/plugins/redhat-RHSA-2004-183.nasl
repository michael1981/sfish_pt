
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12493);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-183:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-183");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix two privilege escalation vulnerabilities
  are now available.

  The Linux kernel handles the basic functions of the operating system.

  iSEC Security Research discovered a flaw in the ip_setsockopt() function
  code of the Linux kernel versions 2.4.22 to 2.4.25 inclusive. This flaw
  also affects the 2.4.21 kernel in Red Hat Enterprise Linux 3 which
  contained a backported version of the affected code. A local user could
  use this flaw to gain root privileges. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0424 to
  this issue.

  iDefense reported a buffer overflow flaw in the ISO9660 filesystem code.
  An attacker could create a malicious filesystem in such a way that root
  privileges may be obtained if the filesystem is mounted. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0109 to this issue.

  All Red Hat Enterprise Linux 3 users are advised to upgrade their kernels
  to the packages associated with their machine architectures and
  configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-183.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0109", "CVE-2004-0424");
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

if ( rpm_check( reference:"  kernel-2.4.21-9.0.3.EL.athlon.rpm                        747381f00d4483d2b680d81a79ee87d0", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-9.0.3.EL.athlon.rpm                    4419e2bc38199f6e108c87c34c29c77f", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-9.0.3.EL.athlon.rpm        c40f0b228e80bd863eeba517a05909c8", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-9.0.3.EL.athlon.rpm            5fef3bbf1605baaea07bd77ff96fff79", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-9.0.3.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
