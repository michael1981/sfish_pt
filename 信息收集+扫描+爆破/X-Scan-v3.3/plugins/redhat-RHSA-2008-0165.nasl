
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31985);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0165: ImageMagick");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0165");
 script_set_attribute(attribute: "description", value: '
  Updated ImageMagick packages that correct several security issues are now
  available for Red Hat Enterprise Linux version 2.1.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  ImageMagick is an image display and manipulation tool for the X Window
  System that can read and write multiple image formats.

  Several heap-based buffer overflow flaws were found in ImageMagick. If a
  victim opened a specially-crafted DCM or XWD file, an attacker could
  potentially execute arbitrary code on the victim\'s machine. (CVE-2007-1797)

  Several denial of service flaws were found in ImageMagick\'s parsing of XCF
  and DCM files. Attempting to process a specially crafted input file in
  these formats could cause ImageMagick to enter an infinite loop.
  (CVE-2007-4985)

  Several integer overflow flaws were found in ImageMagick. If a victim
  opened a specially-crafted DCM, DIB, XBM, XCF or XWD file, an attacker
  could potentially execute arbitrary code with the privileges of the user
  running ImageMagick. (CVE-2007-4986)

  A heap-based buffer overflow flaw was found in ImageMagick\'s processing of
  certain malformed PCX images. If a victim opened a specially-crafted PCX
  file, an attacker could possibly execute arbitrary code with the privileges
  of the user running ImageMagick.. (CVE-2008-1097)

  All users of ImageMagick should upgrade to these updated packages, which
  contain backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0165.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2008-1097");
script_summary(english: "Check for the version of the ImageMagick packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ImageMagick-5.3.8-21", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.3.8-21", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.3.8-21", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.3.8-21", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.3.8-21", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
