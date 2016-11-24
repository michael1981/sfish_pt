
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12401);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2003-195:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-195");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages for Red Hat Enterprise Linux are now available
  which address several security vulnerabilities.

  The Linux kernel handles the basic functions of the operating system.

  Several security issues have been found that affect the Linux kernel:

  Al Viro found a security issue in the tty layer whereby any user could
  cause a kernel oops. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-0247 to this issue.

  Andrea Arcangeli found an issue in the low-level mxcsr code in which a
  malformed address would leave garbage in cpu state registers. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
  name CAN-2003-0248 to this issue.

  The TCP/IP fragment reassembly handling allows remote attackers to cause a
  denial of service (CPU consumption) via packets that cause a large number
  of hash table collisions, a vulnerability similar to CAN-2003-0244. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2003-0364 to this issue.

  These kernels also contain updated fixes for the ioperm security issue, as
  well as fixes for a number of bugs.

  It is recommended that users upgrade to these erratum kernels, which
  contain patches to correct these vulnerabilities.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-195.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2001-1572", "CVE-2003-0247", "CVE-2003-0248", "CVE-2003-0364");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.25.athlon.rpm               cb5811644f7435fa729233b8ab3606a7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.25.athlon.rpm           1f52cfb99a57e475f16f56b2eab18118", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.25", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
