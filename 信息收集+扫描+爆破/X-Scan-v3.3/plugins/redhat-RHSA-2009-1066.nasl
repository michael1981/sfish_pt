
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38922);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1066: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1066");
 script_set_attribute(attribute: "description", value: '
  An updated squirrelmail package that fixes multiple security issues is now
  available for Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  SquirrelMail is a standards-based webmail package written in PHP.

  A server-side code injection flaw was found in the SquirrelMail
  "map_yp_alias" function. If SquirrelMail was configured to retrieve a
  user\'s IMAP server address from a Network Information Service (NIS) server
  via the "map_yp_alias" function, an unauthenticated, remote attacker using
  a specially-crafted username could use this flaw to execute arbitrary code
  with the privileges of the web server. (CVE-2009-1579)

  Multiple cross-site scripting (XSS) flaws were found in SquirrelMail. An
  attacker could construct a carefully crafted URL, which once visited by an
  unsuspecting user, could cause the user\'s web browser to execute malicious
  script in the context of the visited SquirrelMail web page. (CVE-2009-1578)

  It was discovered that SquirrelMail did not properly sanitize Cascading
  Style Sheets (CSS) directives used in HTML mail. A remote attacker could
  send a specially-crafted email that could place mail content above
  SquirrelMail\'s controls, possibly allowing phishing and cross-site
  scripting attacks. (CVE-2009-1581)

  Users of squirrelmail should upgrade to this updated package, which
  contains backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1066.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1578", "CVE-2009-1579", "CVE-2009-1581");
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

if ( rpm_check( reference:"squirrelmail-1.4.8-5.el5_3.7", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-13.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-5.el4_8.5", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-5.el4_8.5", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-5.el5_3.7", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
