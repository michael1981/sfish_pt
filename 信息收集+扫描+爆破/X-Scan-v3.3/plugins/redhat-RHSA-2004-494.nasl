
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15537);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-494: ImageMagick");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-494");
 script_set_attribute(attribute: "description", value: '
  Updated ImageMagick packages that fix various security vulnerabilities are
  now available.

  ImageMagick(TM) is an image display and manipulation tool for the X Window
  System.

  A heap overflow flaw was discovered in the ImageMagick image handler.
  An attacker could create a carefully crafted BMP file in such a way that it
  would cause ImageMagick to execute arbitrary code when processing the
  image. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2004-0827 to this issue.

  A temporary file handling bug has been found in ImageMagick\'s libmagick
  library. A local user could overwrite or create files as a different user
  if a program was linked with the vulnerable library. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2003-0455 to this issue.

  Users of ImageMagick should upgrade to these updated packages, which
  contain a backported patch, and is not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-494.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0455", "CVE-2004-0827");
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

if ( rpm_check( reference:"ImageMagick-5.3.8-5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-5.3.8-5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-c++-devel-5.3.8-5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-5.3.8-5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ImageMagick-perl-5.3.8-5", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
