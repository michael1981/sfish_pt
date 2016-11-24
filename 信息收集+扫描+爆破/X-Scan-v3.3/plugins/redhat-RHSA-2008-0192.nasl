
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31754);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0192: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0192");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX(R) operating systems.

  A heap buffer overflow flaw was found in a CUPS administration interface
  CGI script. A local attacker able to connect to the IPP port (TCP port 631)
  could send a malicious request causing the script to crash or, potentially,
  execute arbitrary code as the "lp" user. Please note: the default CUPS
  configuration in Red Hat Enterprise Linux 5 does not allow remote
  connections to the IPP TCP port. (CVE-2008-0047)

  Red Hat would like to thank "regenrecht" for reporting this issue.

  This issue did not affect the versions of CUPS as shipped with Red Hat
  Enterprise Linux 3 or 4.

  Two overflows were discovered in the HP-GL/2-to-PostScript filter. An
  attacker could create a malicious HP-GL/2 file that could possibly execute
  arbitrary code as the "lp" user if the file is printed. (CVE-2008-0053)

  A buffer overflow flaw was discovered in the GIF decoding routines used by
  CUPS image converting filters "imagetops" and "imagetoraster". An attacker
  could create a malicious GIF file that could possibly execute arbitrary
  code as the "lp" user if the file was printed. (CVE-2008-1373)

  All cups users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0192.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0047", "CVE-2008-0053", "CVE-2008-1373");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.2.4-11.14.el5_1.6", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.2.4-11.14.el5_1.6", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.2.4-11.14.el5_1.6", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-lpd-1.2.4-11.14.el5_1.6", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
