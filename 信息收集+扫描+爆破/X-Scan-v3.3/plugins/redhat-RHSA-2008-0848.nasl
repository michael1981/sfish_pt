
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34064);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0848: libtiff");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0848");
 script_set_attribute(attribute: "description", value: '
  Updated libtiff packages that fix various security issues and a bug are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The libtiff packages contain a library of functions for manipulating Tagged
  Image File Format (TIFF) files.

  Multiple uses of uninitialized values were discovered in libtiff\'s
  Lempel-Ziv-Welch (LZW) compression algorithm decoder. An attacker could
  create a carefully crafted LZW-encoded TIFF file that would cause an
  application linked with libtiff to crash or, possibly, execute arbitrary
  code. (CVE-2008-2327)

  Red Hat would like to thank Drew Yao of the Apple Product Security team for
  reporting this issue.

  A buffer overflow flaw was discovered in the tiff2pdf conversion program
  distributed with libtiff. An attacker could create a TIFF file containing
  UTF-8 characters that would, when converted to PDF format, cause tiff2pdf
  to crash, or, possibly, execute arbitrary code. (CVE-2006-2193)

  Additionally, these updated packages fix the following bug:

  * the libtiff packages included manual pages for the sgi2tiff and tiffsv
  commands, which are not included in these packages. These extraneous manual
  pages were removed.

  All libtiff users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0848.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-2193", "CVE-2008-2327");
script_summary(english: "Check for the version of the libtiff packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libtiff-3.6.1-12.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.6.1-12.el4_7.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
