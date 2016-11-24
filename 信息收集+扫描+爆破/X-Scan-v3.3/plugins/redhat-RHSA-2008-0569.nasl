
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33425);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0569: devhelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0569");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Multiple flaws were found in the processing of malformed JavaScript
  content. A web page containing such malicious content could cause Firefox
  to crash or, potentially, execute arbitrary code as the user running
  Firefox. (CVE-2008-2801, CVE-2008-2802, CVE-2008-2803)

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code as the user running Firefox.
  (CVE-2008-2798, CVE-2008-2799, CVE-2008-2811)

  Several flaws were found in the way malformed web content was displayed. A
  web page containing specially-crafted content could potentially trick a
  Firefox user into surrendering sensitive information. (CVE-2008-2800)

  Two local file disclosure flaws were found in Firefox. A web page
  containing malicious content could cause Firefox to reveal the contents of
  a local file to a remote attacker. (CVE-2008-2805, CVE-2008-2810)

  A flaw was found in the way a malformed .properties file was processed by
  Firefox. A malicious extension could read uninitialized memory, possibly
  leaking sensitive data to the extension. (CVE-2008-2807)

  A flaw was found in the way Firefox escaped a listing of local file names.
  If a user could be tricked into listing a local directory containing
  malicious file names, arbitrary JavaScript could be run with the
  permissions of the user running Firefox. (CVE-2008-2808)

  A flaw was found in the way Firefox displayed information about self-signed
  certificates. It was possible for a self-signed certificate to contain
  multiple alternate name entries, which were not all displayed to the user,
  allowing them to mistakenly extend trust to an unknown site.
  (CVE-2008-2809)

  All Mozilla Firefox users should upgrade to these updated packages, which
  contain backported patches that correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0569.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");
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

if ( rpm_check( reference:"devhelp-0.12-17.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.12-17.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0-2.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"yelp-2.16.0-19.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
