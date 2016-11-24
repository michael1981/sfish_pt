
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40340);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1162: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1162");
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
  (CVE-2009-2462, CVE-2009-2463, CVE-2009-2464, CVE-2009-2465, CVE-2009-2466,
  CVE-2009-2467, CVE-2009-2469, CVE-2009-2471)

  Several flaws were found in the way Firefox handles malformed JavaScript
  code. A website containing malicious content could launch a cross-site
  scripting (XSS) attack or execute arbitrary JavaScript with the permissions
  of another website. (CVE-2009-2472)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.0.12. You can find a link to the Mozilla
  advisories in the References section of this errata.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.12, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1162.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2471", "CVE-2009-2472");
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

if ( rpm_check( reference:"firefox-3.0.12-1.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.12-1.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.12-1.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.12-1.el5_3", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.12-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.12-1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.12-1.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.12-1.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.12-1.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.12-1.el5_3", release:'RHEL5.3.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
