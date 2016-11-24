
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12345);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2002-307: xpdf");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-307");
 script_set_attribute(attribute: "description", value: '
  Updated Xpdf packages are available to fix a vulnerability where a
  malicious PDF document could run arbitrary code.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Xpdf is an X Window System based viewer for Portable Document Format
  (PDF) files.

  During an audit of CUPS, a printing system, Zen Parsec found an integer
  overflow vulnerability in the pdftops filter. Since the code for pdftops
  is taken from the Xpdf project, all versions of Xpdf including 2.01 are
  also vulnerable to this issue. An attacker could create a malicious PDF
  file that would execute arbitrary code as the user who used Xpdf to view
  it.

  All users of Xpdf are advised to upgrade to these errata packages which
  contain a patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-307.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2002-1384");
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

if ( rpm_check( reference:"xpdf-0.92-8", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
