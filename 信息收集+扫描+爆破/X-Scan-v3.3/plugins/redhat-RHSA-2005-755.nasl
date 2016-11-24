
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19544);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-755: elm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-755");
 script_set_attribute(attribute: "description", value: '
  An updated elm package is now available that fixes a buffer overflow issue
  for Red Hat Enterprise Linux 2.1 AS and AW.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Elm is a terminal mode email client.

  A buffer overflow flaw in Elm was discovered that was triggered by viewing
  a mailbox containing a message with a carefully crafted \'Expires\' header.
  An attacker could create a malicious message that would execute arbitrary
  code with the privileges of the user who received it. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-2665 to this issue.

  Users of Elm should update to this updated package, which contains a
  backported patch that corrects this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-755.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2665");
script_summary(english: "Check for the version of the elm packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"elm-2.5.6-6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
