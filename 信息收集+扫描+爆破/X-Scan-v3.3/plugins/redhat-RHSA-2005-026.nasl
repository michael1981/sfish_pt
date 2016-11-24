
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17338);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-026: tetex");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-026");
 script_set_attribute(attribute: "description", value: '
  Updated tetex packages that resolve security issues are now available for
  Red
  Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The tetex packages (teTeX) contain an implementation of TeX for Linux or
  UNIX systems.

  A buffer overflow flaw was found in the Gfx::doImage function of Xpdf which
  also affects teTeX due to a shared codebase. An attacker could construct a
  carefully crafted PDF file that could cause teTeX to crash or possibly
  execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-1125 to
  this issue.

  A buffer overflow flaw was found in the Decrypt::makeFileKey2 function of
  Xpdf which also affects teTeX due to a shared codebase. An attacker could
  construct a carefully crafted PDF file that could cause teTeX to crash or
  possibly execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0064 to
  this issue.

  Users should update to these erratum packages which contain backported
  patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-026.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1125", "CVE-2005-0064");
script_summary(english: "Check for the version of the tetex packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tetex-2.0.2-22.EL4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-2.0.2-22.EL4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-2.0.2-22.EL4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-2.0.2-22.EL4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-2.0.2-22.EL4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-2.0.2-22.EL4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-2.0.2-22.EL4.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
