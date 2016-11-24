
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12458);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2004-044:   kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-044");
 script_set_attribute(attribute: "description", value: '
  Updated kernel packages are now available that fix a few security issues,
  an NFS performance issue, and an e1000 driver loading issue introduced in
  Update 3.

  The Linux kernel handles the basic functions of the operating system.

  Alan Cox found issues in the R128 Direct Render Infrastructure that
  could allow local privilege escalation. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0003 to
  this issue.

  The C-Media PCI sound driver in Linux before 2.4.22 does not use the
  get_user function to access userspace in certain conditions, which crosses
  security boundaries. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-0700 to this issue.

  An overflow was found in the ixj telephony card driver in Linux kernels
  prior to 2.4.20. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2002-1574 to this issue.

  All users are advised to upgrade to these errata packages, which contain
  backported security patches that corrects these issues. These packages
  also contain a fix to enhance NFS performance, which was degraded in the
  last kernel update as part of Update 3.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-044.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1574", "CVE-2003-0700", "CVE-2004-0003");
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

if ( rpm_check( reference:"  kernel-2.4.9-e.37.athlon.rpm               030f252f56b1914712a10882637a791c", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-debug-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-headers-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"  kernel-smp-2.4.9-e.37.athlon.rpm           1d819b13b87cf66ee7bdae9c4ca0ec77", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-summit-2.4.9-e.37", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
