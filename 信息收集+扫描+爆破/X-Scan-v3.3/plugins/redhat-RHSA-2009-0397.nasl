
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36043);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0397: xulrunner");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0397");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix two security issues are now available for
  Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  A memory corruption flaw was discovered in the way Firefox handles XML
  files containing an XSLT transform. A remote attacker could use this flaw
  to crash Firefox or, potentially, execute arbitrary code as the user
  running Firefox. (CVE-2009-1169)

  A flaw was discovered in the way Firefox handles certain XUL garbage
  collection events. A remote attacker could use this flaw to crash Firefox
  or, potentially, execute arbitrary code as the user running Firefox.
  (CVE-2009-1044)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories. You can find a link to the Mozilla advisories in the References
  section of this errata.

  Firefox users should upgrade to these updated packages, which resolve these
  issues. For Red Hat Enterprise Linux 4, they contain backported patches to
  the firefox package. For Red Hat Enterprise Linux 5, they contain
  backported patches to the xulrunner packages. After installing the update,
  Firefox must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0397.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1044", "CVE-2009-1169");
script_summary(english: "Check for the version of the xulrunner packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xulrunner-1.9.0.7-3.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.7-3.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.7-3.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.7-3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
