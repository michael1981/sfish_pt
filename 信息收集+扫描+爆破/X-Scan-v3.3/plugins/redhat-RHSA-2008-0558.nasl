
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33250);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0558: freetype");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0558");
 script_set_attribute(attribute: "description", value: '
  Updated freetype packages that fix various security issues are now
  available for Red Hat Enterprise Linux 2.1.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  [Updated 25th June 2008]
  The original packages distributed with this errata had a bug which
  prevented freetype library from loading certain font files correctly. We
  have updated the packages to correct this bug.

  FreeType is a free, high-quality, portable font engine that can open and
  manage font files, as well as efficiently load, hint and render individual
  glyphs.

  Multiple flaws were discovered in FreeType\'s Printer Font Binary (PFB) and
  TrueType Font (TTF) font-file format parsers. If a user loaded a carefully
  crafted font-file with a program linked against FreeType, it could cause
  the application to crash, or possibly execute arbitrary code.
  (CVE-2008-1806, CVE-2008-1807, CVE-2008-1808)

  Note: the flaw in FreeType\'s TrueType Font (TTF) font-file format parser,
  covered by CVE-2008-1808, only affected the FreeType 1 library (libttf),
  which shipped in the freetype packages in Red Hat Enterprise Linux 2.1. The
  FreeType 2 library (libfreetype) is not affected, as it is not compiled
  with TTF Byte Code Interpreter (BCI) support.

  Users of freetype should upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0558.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
script_summary(english: "Check for the version of the freetype packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"freetype-2.0.3-15.el21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-devel-2.0.3-15.el21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"freetype-utils-2.0.3-15.el21", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
