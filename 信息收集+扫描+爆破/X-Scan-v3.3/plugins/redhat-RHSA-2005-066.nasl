
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17178);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-066: kdegraphics");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-066");
 script_set_attribute(attribute: "description", value: '
  Updated kdegraphics packages that resolve security issues in kpdf are now
  available.

  This update has been rated as having important security impact by the Red
  Hat
  Security Response Team.

  The kdegraphics packages contain applications for the K Desktop Environment
  including kpdf, a pdf file viewer.

  A buffer overflow flaw was found in the Gfx::doImage function of Xpdf that
  also affects kpdf due to a shared codebase. An attacker could construct a
  carefully crafted PDF file that could cause kpdf to crash or possibly
  execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-1125 to
  this issue.

  A buffer overflow flaw was found in the Decrypt::makeFileKey2 function of
  Xpdf which also affects kpdf due to a shared codebase. An attacker could
  construct a carefully crafted PDF file that could cause kpdf to crash or
  possibly execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0064 to
  this issue.

  During a source code audit, Chris Evans and others discovered a number of
  integer overflow bugs that affected all versions of Xpdf which also affects
  kpdf due to a shared codebase. An attacker could construct a carefully
  crafted PDF file that could cause kpdf to crash or possibly execute
  arbitrary code when opened. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-0888 to this issue.

  Users should update to these erratum packages which contain backported
  patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-066.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0888", "CVE-2004-1125", "CVE-2005-0064");
script_summary(english: "Check for the version of the kdegraphics packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdegraphics-3.3.1-3.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.3.1-3.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
