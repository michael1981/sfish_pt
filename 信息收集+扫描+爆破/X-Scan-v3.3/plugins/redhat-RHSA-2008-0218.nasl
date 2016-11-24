
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32420);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0218: gnome");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0218");
 script_set_attribute(attribute: "description", value: '
  An updated gnome-screensaver package that fixes a security flaw is now
  available for Red Hat Enterprise Linux FasTrack 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  gnome-screensaver is the GNOME project\'s official screen saver program.

  A flaw was found in the way gnome-screensaver verified user passwords. When
  a system used a remote directory service for login credentials, a local
  attacker able to cause a network outage could cause gnome-screensaver to
  crash, unlocking the screen. (CVE-2008-0887)

  Users of gnome-screensaver should upgrade to this updated package, which
  contains a backported patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0218.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0887");
script_summary(english: "Check for the version of the gnome packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnome-screensaver-2.16.1-8.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
