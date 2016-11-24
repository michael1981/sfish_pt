
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17149);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-132: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-132");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix a security issue are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX Printing System (CUPS) is a print spooler.

  During a source code audit, Chris Evans discovered a number of integer
  overflow bugs that affect Xpdf. CUPS contained a copy of the Xpdf code
  used for parsing PDF files and was therefore affected by these bugs. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) assigned the
  name CAN-2004-0888 to this issue, and Red Hat released erratum
  RHSA-2004:543 with updated packages.

  It was found that the patch used to correct this issue was not sufficient
  and did not fully protect CUPS running on 64-bit architectures. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0206 to this issue.

  These updated packages also include a fix that prevents the CUPS
  initscript from being accidentally replaced.

  All users of CUPS on 64-bit architectures should upgrade to these updated
  packages, which contain a corrected patch and are not vulnerable to these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-132.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0206");
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

if ( rpm_check( reference:"cups-1.1.17-13.3.27", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.27", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.27", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
