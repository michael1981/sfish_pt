
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12500);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-233: cvs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-233");
 script_set_attribute(attribute: "description", value: '
  An updated cvs package that fixes several server vulnerabilities, which
  could
  be exploited by a malicious client, is now available.

  CVS is a version control system frequently used to manage source code
  repositories.

  While investigating a previously fixed vulnerability, Derek Price
  discovered a flaw relating to malformed "Entry" lines which lead to a
  missing NULL terminator. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2004-0414 to this issue.

  Stefan Esser and Sebastian Krahmer conducted an audit of CVS and fixed a
  number of issues that may have had security consequences.

  Among the issues deemed likely to be exploitable were:

  -- a double-free relating to the error_prog_name string (CAN-2004-0416)
  -- an argument integer overflow (CAN-2004-0417)
  -- out-of-bounds writes in serv_notify (CAN-2004-0418).

  An attacker who has access to a CVS server may be able to execute arbitrary
  code under the UID on which the CVS server is executing.

  Users of CVS are advised to upgrade to this updated package, which contains
  backported patches correcting these issues.

  Red Hat would like to thank Stefan Esser, Sebastian Krahmer, and Derek
  Price for auditing, disclosing, and providing patches for these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-233.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0414", "CVE-2004-0416", "CVE-2004-0417", "CVE-2004-0418", "CVE-2004-0778");
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

if ( rpm_check( reference:"cvs-1.11.1p1-16", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.2-24", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
