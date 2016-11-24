
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27839);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1030: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1030");
 script_set_attribute(attribute: "description", value: '
  Updated xpdf packages that fix several security issues are now available
  for Red Hat Enterprise Linux 3.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Xpdf is an X Window System-based viewer for Portable Document Format (PDF)
  files.

  Alin Rad Pop discovered several flaws in the handling of PDF files. An
  attacker could create a malicious PDF file that would cause Xpdf to crash,
  or potentially execute arbitrary code when opened.
  (CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)

  A flaw was found in the t1lib library, used in the handling of Type 1
  fonts. An attacker could create a malicious file that would cause Xpdf to
  crash, or potentially execute arbitrary code when opened. (CVE-2007-4033)

  Users are advised to upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1030.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4033", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
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

if ( rpm_check( reference:"xpdf-2.02-11.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
