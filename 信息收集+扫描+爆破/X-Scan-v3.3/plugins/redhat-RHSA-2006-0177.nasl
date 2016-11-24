
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20482);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0177: gpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0177");
 script_set_attribute(attribute: "description", value: '
  An updated gpdf package that fixes several security issues is now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  gpdf is a GNOME based viewer for Portable Document Format (PDF) files.

  Chris Evans discovered several flaws in the way gpdf processes PDF files.
  An attacker could construct a carefully crafted PDF file that could cause
  gpdf to crash or possibly execute arbitrary code when opened. The Common
  Vulnerabilities and Exposures project assigned the names CVE-2005-3624,
  CVE-2005-3625, CVE-2005-3626, and CVE-2005-3627 to these issues.

  Users of gpdf should upgrade to this updated package, which contains a
  backported patch to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0177.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");
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

if ( rpm_check( reference:"gpdf-2.8.2-7.4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
