
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17310);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-215: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-215");
 script_set_attribute(attribute: "description", value: '
  An updated gaim package that fixes various security issues as well as a
  number of bugs is now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Gaim application is a multi-protocol instant messaging client.

  Two HTML parsing bugs were discovered in Gaim. It is possible that a remote
  attacker could send a specially crafted message to a Gaim client, causing
  it to crash. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CAN-2005-0208 and CAN-2005-0473 to
  these issues.

  A bug in the way Gaim processes SNAC packets was discovered. It is
  possible that a remote attacker could send a specially crafted SNAC packet
  to a Gaim client, causing the client to stop responding. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0472 to this issue.

  Additionally, various client crashes, memory leaks, and protocol issues
  have been resolved.

  Users of Gaim are advised to upgrade to this updated package which contains
  Gaim version 1.1.4 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-215.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0208", "CVE-2005-0472", "CVE-2005-0473");
script_summary(english: "Check for the version of the gaim packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gaim-1.1.4-1.EL3.1", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-1.1.4-1.EL4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
