
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21363);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0283: squirrelmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0283");
 script_set_attribute(attribute: "description", value: '
  An updated squirrelmail package that fixes three security and many other
  bug issues is now available. This update contains bug fixes of upstream
  squirrelmail 1.4.6 with some additional improvements to international
  language support.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  SquirrelMail is a standards-based webmail package written in PHP4.

  A bug was found in the way SquirrelMail presents the right frame to the
  user. If a user can be tricked into opening a carefully crafted URL, it is
  possible to present the user with arbitrary HTML data. (CVE-2006-0188)

  A bug was found in the way SquirrelMail filters incoming HTML email. It is
  possible to cause a victim\'s web browser to request remote content by
  opening a HTML email while running a web browser that processes certain
  types of invalid style sheets. Only Internet Explorer is known to process
  such malformed style sheets. (CVE-2006-0195)

  A bug was found in the way SquirrelMail processes a request to select an
  IMAP mailbox. If a user can be tricked into opening a carefully crafted
  URL, it is possible to execute arbitrary IMAP commands as the user viewing
  their mail with SquirrelMail. (CVE-2006-0377)

  Users of SquirrelMail are advised to upgrade to this updated package, which
  contains SquirrelMail version 1.4.6 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0283.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0188", "CVE-2006-0195", "CVE-2006-0377");
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

if ( rpm_check( reference:"squirrelmail-1.4.6-5.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squirrelmail-1.4.6-5.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
