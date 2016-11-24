
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21005);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0232: tar");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0232");
 script_set_attribute(attribute: "description", value: '
  An updated tar package that fixes a buffer overflow bug is now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having Moderate security impact by the Red
  Hat Security Response Team.

  The GNU tar program saves many files together in one archive and can
  restore individual files (or all of the files) from that archive.

  Jim Meyering discovered a buffer overflow bug in the way GNU tar extracts
  malformed archives. By tricking a user into extracting a malicious tar
  archive, it is possible to execute arbitrary code as the user running tar.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) assigned
  the name CVE-2006-0300 to this issue.

  Users of tar should upgrade to this updated package, which contains a
  backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0232.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0300");
script_summary(english: "Check for the version of the tar packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tar-1.14-9.RHEL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
