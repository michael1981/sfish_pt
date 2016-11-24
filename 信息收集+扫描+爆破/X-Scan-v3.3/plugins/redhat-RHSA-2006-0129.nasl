
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21032);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0129: spamassassin");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0129");
 script_set_attribute(attribute: "description", value: '
  An updated spamassassin package that fixes a denial of service flaw is now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SpamAssassin provides a way to reduce unsolicited commercial email (SPAM)
  from incoming email.

  A denial of service bug was found in SpamAssassin. An attacker could
  construct a message in such a way that would cause SpamAssassin to crash.
  If a number of these messages are sent, it could lead to a denial of
  service, potentially preventing the delivery or filtering of email. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) assigned the
  name CVE-2005-3351 to this issue.

  The following issues have also been fixed in this update:

  * service spamassassin restart sometimes fails
  * Content Boundary "--" throws off message parser
  * sa-learn: massive memory usage on large messages
  * High memory usage with many newlines
  * service spamassassin messages not translated
  * Numerous other bug fixes that improve spam filter accuracy and safety

  Users of SpamAssassin should upgrade to this updated package containing
  version 3.0.5, which is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0129.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3351");
script_summary(english: "Check for the version of the spamassassin packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"spamassassin-3.0.5-3.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
