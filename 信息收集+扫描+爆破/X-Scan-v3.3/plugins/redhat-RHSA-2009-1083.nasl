
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39307);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1083: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1083");
 script_set_attribute(attribute: "description", value: '
  Updated cups packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Common UNIX® Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems. The Internet Printing Protocol (IPP) allows
  users to print and manage printing-related tasks over a network. The CUPS
  "pdftops" filter converts Portable Document Format (PDF) files to
  PostScript. "pdftops" is based on Xpdf and the CUPS imaging library.

  A NULL pointer dereference flaw was found in the CUPS IPP routine, used for
  processing incoming IPP requests for the CUPS scheduler. An attacker could
  use this flaw to send specially-crafted IPP requests that would crash the
  cupsd daemon. (CVE-2009-0949)

  A use-after-free flaw was found in the CUPS scheduler directory services
  routine, used to process data about available printers and printer classes.
  An attacker could use this flaw to cause a denial of service (cupsd daemon
  stop or crash). (CVE-2009-1196)

  Multiple integer overflows flaws, leading to heap-based buffer overflows,
  were found in the CUPS "pdftops" filter. An attacker could create a
  malicious PDF file that would cause "pdftops" to crash or, potentially,
  execute arbitrary code as the "lp" user if the file was printed.
  (CVE-2009-0791)

  Red Hat would like to thank Anibal Sacco from Core Security Technologies
  for reporting the CVE-2009-0949 flaw, and Swen van Brussel for reporting
  the CVE-2009-1196 flaw.

  Users of cups are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing this
  update, the cupsd daemon will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1083.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0791", "CVE-2009-0949", "CVE-2009-1196");
script_summary(english: "Check for the version of the cups packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.1.17-13.3.62", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.17-13.3.62", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.17-13.3.62", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.22-0.rc1.9.32.el4_8.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.9.32.el4_8.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.9.32.el4_8.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-1.1.22-0.rc1.9.32.el4_8.3", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-devel-1.1.22-0.rc1.9.32.el4_8.3", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-libs-1.1.22-0.rc1.9.32.el4_8.3", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
