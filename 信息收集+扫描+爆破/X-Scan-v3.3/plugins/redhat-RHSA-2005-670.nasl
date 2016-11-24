
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19410);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-670: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-670");
 script_set_attribute(attribute: "description", value: '
  An updated xpdf package that fixes a security issue is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The xpdf package is an X Window System-based viewer for Portable Document
  Format (PDF) files.

  A flaw was discovered in Xpdf in that an attacker could construct a
  carefully crafted PDF file that would cause Xpdf to consume all available
  disk space in /tmp when opened. The Common Vulnerabilities and Exposures
  project assigned the name CAN-2005-2097 to this issue.

  Note this issue does not affect the version of Xpdf in Red Hat Enterprise
  Linux 3 or 2.1.

  Users of xpdf should upgrade to this updated package, which contains a
  backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-670.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2097");
script_summary(english: "Check for the version of the xpdf packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xpdf-3.00-11.8", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
