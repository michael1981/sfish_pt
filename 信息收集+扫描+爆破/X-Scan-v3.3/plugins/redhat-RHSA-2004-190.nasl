
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12495);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2004-190: cvs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-190");
 script_set_attribute(attribute: "description", value: '
  An updated cvs package that fixes a server vulnerability that could be
  exploited by a malicious client is now available.

  CVS is a version control system frequently used to manage source code
  repositories.

  Stefan Esser discovered a flaw in cvs where malformed "Entry"
  lines could cause a heap overflow. An attacker who has access to a CVS
  server could use this flaw to execute arbitrary code under the UID which
  the CVS server is executing. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-0396 to this issue.

  Users of CVS are advised to upgrade to this updated package, which contains
  a backported patch correcting this issue.

  Red Hat would like to thank Stefan Esser for notifying us of this issue and
  Derek Price for providing an updated patch.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-190.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0396");
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

if ( rpm_check( reference:"cvs-1.11.1p1-14", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-22", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
