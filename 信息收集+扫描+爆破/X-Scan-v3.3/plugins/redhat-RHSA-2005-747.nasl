
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19490);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-747: slocate");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-747");
 script_set_attribute(attribute: "description", value: '
  An updated slocate package that fixes a denial of service issue is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Slocate is a security-enhanced version of locate. Like locate, slocate
  searches through a nightly-updated central database for files that match a
  given pattern.

  A bug was found in the way slocate processes very long paths. A local user
  could create a carefully crafted directory structure that would prevent
  updatedb from completing its file system scan, resulting in an incomplete
  slocate database. The Common Vulnerabilities and Exposures project has
  assigned the name CAN-2005-2499 to this issue.

  Users are advised to upgrade to this updated package, which includes a
  backported patch to resolve this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-747.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2499");
script_summary(english: "Check for the version of the slocate packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"slocate-2.7-1.el2.1", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
