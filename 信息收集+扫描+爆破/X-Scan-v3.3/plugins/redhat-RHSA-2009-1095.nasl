
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39369);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1095: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1095");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code as the user running Firefox.
  (CVE-2009-1392, CVE-2009-1832, CVE-2009-1833, CVE-2009-1837, CVE-2009-1838,
  CVE-2009-1841)

  Multiple flaws were found in the processing of malformed, local file
  content. If a user loaded malicious, local content via the file:// URL, it
  was possible for that content to access other local data. (CVE-2009-1835,
  CVE-2009-1839)

  A script, privilege elevation flaw was found in the way Firefox loaded XML
  User Interface Language (XUL) scripts. Firefox and certain add-ons could
  load malicious content when certain policy checks did not happen.
  (CVE-2009-1840)

  A flaw was found in the way Firefox displayed certain Unicode characters in
  International Domain Names (IDN). If an IDN contained invalid characters,
  they may have been displayed as spaces, making it appear to the user that
  they were visiting a trusted site. (CVE-2009-1834)

  A flaw was found in the way Firefox handled error responses returned from
  proxy servers. If an attacker is able to conduct a man-in-the-middle attack
  against a Firefox instance that is using a proxy server, they may be able
  to steal sensitive information from the site the user is visiting.
  (CVE-2009-1836)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.0.11. You can find a link to the Mozilla
  advisories in the References section of this errata.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.11, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1095.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");
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

if ( rpm_check( reference:"firefox-3.0.11-2.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.11-3.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.11-3.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.11-3.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.11-4.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.11-4.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.11-2.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.11-3.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.11-3.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.11-3.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
