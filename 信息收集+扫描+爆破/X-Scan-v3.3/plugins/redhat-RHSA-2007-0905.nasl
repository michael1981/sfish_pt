
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(26951);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0905: kdebase");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0905");
 script_set_attribute(attribute: "description", value: '
  Updated kdebase packages that resolve several security flaws are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat
  Security Response Team.

  The kdebase packages provide the core applications for KDE, the K Desktop
  Environment. These core packages include Konqueror, the web browser and
  file manager.

  These updated packages address the following vulnerabilities:

  Kees Huijgen found a flaw in the way KDM handled logins when autologin and
  "shutdown with password" were enabled. A local user would have been able
  to login via KDM as any user without requiring a password. (CVE-2007-4569)

  Two Konqueror address spoofing flaws were discovered. A malicious web site
  could spoof the Konqueror address bar, tricking a victim into believing the
  page was from a different site. (CVE-2007-3820, CVE-2007-4224)

  Users of KDE should upgrade to these updated packages, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0905.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3820", "CVE-2007-4224", "CVE-2007-4569");
script_summary(english: "Check for the version of the kdebase packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdebase-3.5.4-15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.5.4-15.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-3.3.1-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-3.3.1-6.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
