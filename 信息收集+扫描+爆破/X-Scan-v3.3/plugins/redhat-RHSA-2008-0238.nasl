
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32020);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0238: kdegraphics");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0238");
 script_set_attribute(attribute: "description", value: '
  Updated kdegraphics packages that fix a security issue are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The kdegraphics packages contain applications for the K Desktop
  Environment, including kpdf, a PDF file viewer.

  Kees Cook discovered a flaw in the way kpdf displayed malformed fonts
  embedded in PDF files. An attacker could create a malicious PDF file that
  would cause kpdf to crash, or, potentially, execute arbitrary code when
  opened. (CVE-2008-1693)

  All kdegraphics users are advised to upgrade to these updated packages,
  which contain backported patches to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0238.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1693");
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

if ( rpm_check( reference:"kdegraphics-3.3.1-9.el4_6", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-3.3.1-9.el4_6", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
