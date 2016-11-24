
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35585);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0256: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0256");
 script_set_attribute(attribute: "description", value: '
  An updated firefox package that fixes various security issues is now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code as the user running Firefox.
  (CVE-2009-0352, CVE-2009-0353, CVE-2009-0356)

  Several flaws were found in the way malformed content was processed. A
  website containing specially-crafted content could, potentially, trick a
  Firefox user into surrendering sensitive information. (CVE-2009-0354,
  CVE-2009-0355)

  A flaw was found in the way Firefox treated HTTPOnly cookies. An attacker
  able to execute arbitrary JavaScript on a target site using HTTPOnly
  cookies may be able to use this flaw to steal the cookie. (CVE-2009-0357)

  A flaw was found in the way Firefox treated certain HTTP page caching
  directives. A local attacker could steal the contents of sensitive pages
  which the page author did not intend to be cached. (CVE-2009-0358)

  For technical details regarding these flaws, please see the Mozilla
  security advisories for Firefox 3.0.6. You can find a link to the Mozilla
  advisories in the References section.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.6, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0256.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
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

if ( rpm_check( reference:"firefox-3.0.6-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss-3.12.2.0-4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss-devel-3.12.2.0-4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss-pkcs11-devel-3.12.2.0-4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss-tools-3.12.2.0-4.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.6-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.6-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.6-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.6-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss-3.12.2.0-3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss-devel-3.12.2.0-3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss-tools-3.12.2.0-3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
