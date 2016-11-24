
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33528);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0597: devhelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0597");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix various security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  [Updated 16th July 2008]
  The nspluginwrapper package has been added to this advisory to satisfy a
  missing package dependency issue.

  Mozilla Firefox is an open source Web browser.

  An integer overflow flaw was found in the way Firefox displayed certain web
  content. A malicious web site could cause Firefox to crash, or execute
  arbitrary code with the permissions of the user running Firefox.
  (CVE-2008-2785)

  A flaw was found in the way Firefox handled certain command line URLs. If
  another application passed Firefox a malformed URL, it could result in
  Firefox executing local malicious content with chrome privileges.
  (CVE-2008-2933)

  All firefox users should upgrade to these updated packages, which contain
  Firefox 3.0.1 that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0597.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2785", "CVE-2008-2933", "CVE-2008-3198");
script_summary(english: "Check for the version of the devhelp packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"devhelp-0.12-18.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.12-18.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.1-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspluginwrapper-0.9.91.5-22.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.1-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.1-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.1-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"yelp-2.16.0-20.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
