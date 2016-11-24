
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25988);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0873: star");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0873");
 script_set_attribute(attribute: "description", value: '
  An updated star package that fixes a path traversal flaw is now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Star is a tar-like archiver. It saves multiple files into a single tape or
  disk archive, and can restore individual files from the archive. Star
  includes multi-volume support, automatic archive format detection and ACL
  support.

  A path traversal flaw was discovered in the way star extracted archives. A
  malicious user could create a tar archive that would cause star to write to
  arbitrary files to which the user running star had write access.
  (CVE-2007-4134)

  Red Hat would like to thank Robert Buchholz for reporting this issue.

  As well, this update adds the command line argument "-.." to the Red Hat
  Enterprise Linux 3 version of star. This allows star to extract files
  containing "/../" in their pathname.

  Users of star should upgrade to this updated package, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0873.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4134");
script_summary(english: "Check for the version of the star packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"star-1.5a75-2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"star-1.5a08-5", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"star-1.5a25-8", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
