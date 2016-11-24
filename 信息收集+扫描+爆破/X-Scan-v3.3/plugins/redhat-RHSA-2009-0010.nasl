
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35357);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0010: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0010");
 script_set_attribute(attribute: "description", value: '
  An updated squirrelmail package that resolves various security issues is
  now available for Red Hat Enterprise Linux 3, 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SquirrelMail is an easy-to-configure, standards-based, webmail package
  written in PHP. It includes built-in PHP support for the IMAP and SMTP
  protocols, and pure HTML 4.0 page-rendering (with no JavaScript required)
  for maximum browser-compatibility, strong MIME support, address books, and
  folder manipulation.

  Ivan Markovic discovered a cross-site scripting (XSS) flaw in SquirrelMail
  caused by insufficient HTML mail sanitization. A remote attacker could send
  a specially-crafted HTML mail or attachment that could cause a user\'s Web
  browser to execute a malicious script in the context of the SquirrelMail
  session when that email or attachment was opened by the user.
  (CVE-2008-2379)

  It was discovered that SquirrelMail allowed cookies over insecure
  connections (ie did not restrict cookies to HTTPS connections). An attacker
  who controlled the communication channel between a user and the
  SquirrelMail server, or who was able to sniff the user\'s network
  communication, could use this flaw to obtain the user\'s session cookie, if
  a user made an HTTP request to the server. (CVE-2008-3663)

  Note: After applying this update, all session cookies set for SquirrelMail
  sessions started over HTTPS connections will have the "secure" flag set.
  That is, browsers will only send such cookies over an HTTPS connection. If
  needed, you can revert to the previous behavior by setting the
  configuration option "$only_secure_cookies" to "false" in SquirrelMail\'s
  /etc/squirrelmail/config.php configuration file.

  Users of squirrelmail should upgrade to this updated package, which
  contains backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0010.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2379", "CVE-2008-3663");
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

if ( rpm_check( reference:"squirrelmail-1.4.8-5.el5_2.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-8.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.8-5.el4_7.2", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
