
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(14239);
 script_version ("$Revision: 1.11 $");
 script_name(english: "RHSA-2004-413:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-413");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages that fix several security issues in Red Hat
  Enterprise Linux 3 are now available.

  The Linux kernel handles the basic functions of the operating system.

  Paul Starzetz discovered flaws in the Linux kernel when handling file
  offset pointers. These consist of invalid conversions of 64 to 32-bit file
  offset pointers and possible race conditions. A local unprivileged user
  could make use of these flaws to access large portions of kernel memory.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2004-0415 to this issue.

  These packages contain a patch written by Al Viro to correct these flaws.
  Red Hat would like to thank iSEC Security Research for disclosing this
  issue and a number of vendor-sec participants for reviewing and working on
  the patch to this issue.

  In addition, these packages correct a number of minor security issues:

  An bug in the e1000 network driver. This bug could be used by local users
  to leak small amounts of kernel memory (CAN-2004-0535).

  A bug in the SoundBlaster 16 code which does not properly handle certain
  sample sizes. This flaw could be used by local users to crash a system
  (CAN-2004-0178).

  A possible NULL-pointer dereference in the Linux kernel prior to 2.4.26 on
  the Itanium platform could allow a local user to crash a system
  (CAN-2004-0447).

  Inappropriate permissions on /proc/scsi/qla2300/HbaApiNode (CAN-2004-0587).

  All Red Hat Enterprise Linux 3 users are advised to upgrade their
  kernels to the packages associated with their machine architectures
  and configurations as listed in this erratum.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-413.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0178", "CVE-2004-0415", "CVE-2004-0447", "CVE-2004-0535", "CVE-2004-0587");
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

if ( rpm_check( reference:"  kernel-2.4.21-15.0.4.EL.athlon.rpm                        25e7d097ccf85396dfdc53c6b03d83ea", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-hugemem-unsupported-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.21-15.0.4.EL.athlon.rpm                    d619cffe546f2f41e9259ac437f07d44", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-unsupported-2.4.21-15.0.4.EL.athlon.rpm        06ef0da24796cc19d9c492e8ab638a29", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-unsupported-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-unsupported-2.4.21-15.0.4.EL.athlon.rpm            388a7af25fbefd195f9ab59922cca912", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-unsupported-2.4.21-15.0.4.EL", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
