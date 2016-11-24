
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18019);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-365: gaim");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-365");
 script_set_attribute(attribute: "description", value: '
  An updated gaim package that fixes multiple denial of service issues is now
  available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The Gaim application is a multi-protocol instant messaging client.

  A buffer overflow bug was found in the way gaim escapes HTML. It is
  possible that a remote attacker could send a specially crafted message to a
  Gaim client, causing it to crash. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-0965 to this issue.

  A bug was found in several of gaim\'s IRC processing functions. These
  functions fail to properly remove various markup tags within an IRC
  message. It is possible that a remote attacker could send a specially
  crafted message to a Gaim client connected to an IRC server, causing it to
  crash. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CAN-2005-0966 to this issue.

  A bug was found in gaim\'s Jabber message parser. It is possible for a
  remote Jabber user to send a specially crafted message to a Gaim client,
  causing it to crash. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0967 to this issue.

  In addition to these denial of service issues, multiple minor upstream
  bugfixes are included in this update.

  Users of Gaim are advised to upgrade to this updated package which contains
  Gaim version 1.2.1 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-365.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0965", "CVE-2005-0966", "CVE-2005-0967");
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

if ( rpm_check( reference:"gaim-1.2.1-4.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gaim-1.2.1-4.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
