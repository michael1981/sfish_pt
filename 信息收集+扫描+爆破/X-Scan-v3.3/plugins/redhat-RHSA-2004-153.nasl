
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12484);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-153: cvs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-153");
 script_set_attribute(attribute: "description", value: '
  Updated cvs packages that fix a client vulnerability that could be
  exploited by a malicious server are now available.

  [Updated Apr 19 2004]
  The description text has been updated to include CAN-2004-0405 which was
  also fixed but not mentioned when this advisory was first released. There
  has been no change to the packages associated with this advisory.

  CVS is a version control system frequently used to manage source code
  repositories.

  Sebastian Krahmer discovered a flaw in CVS clients where rcs diff files can
  create files with absolute pathnames. An attacker could create a fake
  malicious CVS server that would cause arbitrary files to be created or
  overwritten when a victim connects to it. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0180 to
  this issue.

  Derek Price discovered a vulnerability whereby a CVS pserver could be
  abused by a malicious client to view the contents of certain files outside
  of the CVS root directory using relative pathnames containing "../". The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0405 to this issue.

  Users of CVS are advised to upgrade to these erratum packages, which
  contain a patch correcting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-153.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0180", "CVE-2004-0405");
script_summary(english: "Check for the version of the cvs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cvs-1.11.1p1-12", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-18", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
