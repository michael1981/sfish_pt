
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17185);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-099: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-099");
 script_set_attribute(attribute: "description", value: '
  An updated Squirrelmail package that fixes several security issues is now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  SquirrelMail is a standards-based webmail package written in PHP4.

  Jimmy Conner discovered a missing variable initialization in Squirrelmail.
  This flaw could allow potential insecure file inclusions on servers where
  the PHP setting "register_globals" is set to "On". This is not a default or
  recommended setting. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0075 to this issue.

  A URL sanitisation bug was found in Squirrelmail. This flaw could allow a
  cross site scripting attack when loading the URL for the sidebar. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-0103 to this issue.

  A missing variable initialization bug was found in Squirrelmail. This flaw
  could allow a cross site scripting attack. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0104 to
  this issue.

  Users of Squirrelmail are advised to upgrade to this updated package,
  which contains backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-099.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0075", "CVE-2005-0103", "CVE-2005-0104");
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

if ( rpm_check( reference:"squirrelmail-1.4.3a-9.EL4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
