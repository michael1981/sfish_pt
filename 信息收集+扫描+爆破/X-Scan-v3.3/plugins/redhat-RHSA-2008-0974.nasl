
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40730);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2008-0974: acroread");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0974");
 script_set_attribute(attribute: "description", value: '
  Updated acroread packages that fix various security issues are now
  available for Red Hat Enterprise Linux 3 Extras, Red Hat Enterprise Linux 4
  Extras, and Red Hat Enterprise Linux 5 Supplementary.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Adobe Reader allows users to view and print documents in Portable Document
  Format (PDF).

  Several input validation flaws were discovered in Adobe Reader. A malicious
  PDF file could cause Adobe Reader to crash or, potentially, execute
  arbitrary code as the user running Adobe Reader. (CVE-2008-2549,
  CVE-2008-2992, CVE-2008-4812, CVE-2008-4813, CVE-2008-4814, CVE-2008-4817)

  The Adobe Reader binary had an insecure relative RPATH (runtime library
  search path) set in the ELF (Executable and Linking Format) header. A local
  attacker able to convince another user to run Adobe Reader in an
  attacker-controlled directory could run arbitrary code with the privileges
  of the victim. (CVE-2008-4815)

  All acroread users are advised to upgrade to these updated packages, that
  contain Adobe Reader version 8.1.3, and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0974.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2549", "CVE-2008-2992", "CVE-2008-4812", "CVE-2008-4813", "CVE-2008-4814", "CVE-2008-4815", "CVE-2008-4817", "CVE-2009-0927");
script_summary(english: "Check for the version of the acroread packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"acroread-8.1.3-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-8.1.3-1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-8.1.3-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-8.1.3-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-8.1.3-1.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-8.1.3-1.el4", release:'RHEL4.7.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
