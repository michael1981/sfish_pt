
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18387);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-434: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-434");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix various security bugs are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Several bugs were found in the way Firefox executes javascript code.
  Javascript executed from a web page should run with a restricted access
  level, preventing dangerous actions. It is possible that a malicious web
  page could execute javascript code with elevated privileges, allowing
  access to protected data and functions. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the names CAN-2005-1476,
  CAN-2005-1477, CAN-2005-1531, and CAN-2005-1532 to these issues.

  Please note that the effects of CAN-2005-1477 are mitigated by the default
  setup, which allows only the Mozilla Update site to attempt installation of
  Firefox extensions. The Mozilla Update site has been modified to prevent
  this attack from working. If other URLs have been manually added to the
  whitelist, it may be possible to execute this attack.

  Users of Firefox are advised to upgrade to this updated package which
  contains Firefox version 1.0.4 which is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-434.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1476", "CVE-2005-1477", "CVE-2005-1531", "CVE-2005-1532");
script_summary(english: "Check for the version of the firefox packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"firefox-1.0.4-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
