
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18197);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-397: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-397");
 script_set_attribute(attribute: "description", value: '
  Updated evolution packages that fix various security issues are now
  available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Evolution is a GNOME-based collection of personal information management
  (PIM) tools.

  A bug was found in the way Evolution displays mail messages. It is possible
  that an attacker could create a specially crafted mail message that when
  opened by a victim causes Evolution to stop responding. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0806 to this issue.

  A bug was also found in Evolution\'s helper program camel-lock-helper. This
  bug could allow a local attacker to gain root privileges if
  camel-lock-helper has been built to execute with elevated privileges. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-0102 to this issue. On Red Hat Enterprise Linux,
  camel-lock-helper is not built to execute with elevated privileges by
  default. Please note however that if users have rebuilt Evolution from the
  source RPM, as the root user, camel-lock-helper may be given elevated
  privileges.

  All users of evolution should upgrade to these updated packages, which
  include backported fixes to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-397.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0102", "CVE-2005-0806");
script_summary(english: "Check for the version of the evolution packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"evolution-2.0.2-16", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-2.0.2-16", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
