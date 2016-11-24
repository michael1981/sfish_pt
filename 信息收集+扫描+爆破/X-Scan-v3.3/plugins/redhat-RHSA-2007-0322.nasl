
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25158);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0322: xscreensaver");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0322");
 script_set_attribute(attribute: "description", value: '
  An updated xscreensaver package that fixes a security flaw is now
  available for Red Hat Enterprise Linux 2.1, 3, and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  XScreenSaver is a collection of screensavers.

  Alex Yamauchi discovered a flaw in the way XScreenSaver verifies user
  passwords. When a system is using a remote directory service for login
  credentials, a local attacker may be able to cause a network outage causing
  XScreenSaver to crash, unlocking the screen. (CVE-2007-1859)

  Users of XScreenSaver should upgrade to this updated package, which
  contains a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0322.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1859");
script_summary(english: "Check for the version of the xscreensaver packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xscreensaver-3.33-4.rhel21.5", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xscreensaver-4.10-21.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xscreensaver-4.18-5.rhel4.14", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
