
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42162);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1503: gpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1503");
 script_set_attribute(attribute: "description", value: '
  An updated gpdf package that fixes multiple security issues is now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  GPdf is a viewer for Portable Document Format (PDF) files.

  Multiple integer overflow flaws were found in GPdf. An attacker could
  create a malicious PDF file that would cause GPdf to crash or, potentially,
  execute arbitrary code when opened. (CVE-2009-0791, CVE-2009-1188,
  CVE-2009-3604, CVE-2009-3608, CVE-2009-3609)

  Red Hat would like to thank Adam Zabrocki for reporting the CVE-2009-3604
  issue, and Chris Rohlf for reporting the CVE-2009-3608 issue.

  Users are advised to upgrade to this updated package, which contains a
  backported patch to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1503.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0791", "CVE-2009-1188", "CVE-2009-3604", "CVE-2009-3608", "CVE-2009-3609");
script_summary(english: "Check for the version of the gpdf packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gpdf-2.8.2-7.7.2.el4_8.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gpdf-2.8.2-7.7.2.el4_8.5", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
