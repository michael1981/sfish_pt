
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12503);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-240: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-240");
 script_set_attribute(attribute: "description", value: '
  An updated SquirrelMail package that fixes several security vulnerabilities
  is now available.

  SquirrelMail is a webmail package written in PHP. Multiple
  vulnerabilities have been found which affect the version of SquirrelMail
  shipped with Red Hat Enterprise Linux 3.

  An SQL injection flaw was found in SquirrelMail version 1.4.2 and earlier.
  If SquirrelMail is configured to store user addressbooks in the database, a
  remote attacker could use this flaw to execute arbitrary SQL statements.
  The Common Vulnerabilities and Exposures project has assigned the name
  CAN-2004-0521 to this issue.

  A number of cross-site scripting (XSS) flaws in SquirrelMail version 1.4.2
  and earlier could allow remote attackers to execute script as other web
  users. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CAN-2004-0519 and CAN-2004-0520 to these issues.

  All users of SquirrelMail are advised to upgrade to the erratum package
  containing SquirrelMail version 1.4.3a which is not vulnerable to these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-240.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0519", "CVE-2004-0520", "CVE-2004-0521");
script_summary(english: "Check for the version of the squirrelmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squirrelmail-1.4.3-0.e3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
