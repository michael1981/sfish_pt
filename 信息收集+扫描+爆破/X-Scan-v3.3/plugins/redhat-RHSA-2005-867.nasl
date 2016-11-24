
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20362);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-867: gpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-867");
 script_set_attribute(attribute: "description", value: '
  An updated gpdf package that fixes several security issues is now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The gpdf package is a GNOME based viewer for Portable Document Format
  (PDF) files.

  Several flaws were discovered in gpdf. An attacker could construct a
  carefully crafted PDF file that could cause gpdf to crash or possibly
  execute arbitrary code when opened. The Common Vulnerabilities and
  Exposures project assigned the names CVE-2005-3191, CVE-2005-3192, and
  CVE-2005-3193 to these issues.

  Users of gpdf should upgrade to this updated package, which contains a
  backported patch to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-867.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3628");
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

if ( rpm_check( reference:"gpdf-2.8.2-7.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
