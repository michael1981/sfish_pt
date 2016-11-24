
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20208);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-839: lynx");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-839");
 script_set_attribute(attribute: "description", value: '
  An updated lynx package that corrects a security flaw is now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Lynx is a text-based Web browser.

  An arbitrary command execute bug was found in the lynx "lynxcgi:" URI
  handler. An attacker could create a web page redirecting to a malicious URL
  which could execute arbitrary code as the user running lynx. The Common
  Vulnerabilities and Exposures project assigned the name CVE-2005-2929 to
  this issue.

  Users should update to this erratum package, which contains a backported
  patch to correct this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-839.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2929");
script_summary(english: "Check for the version of the lynx packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"lynx-2.8.4-18.1.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-11.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"lynx-2.8.5-18.2", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
