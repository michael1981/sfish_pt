
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40921);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1430: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1430");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox. nspr provides the Netscape
  Portable Runtime (NSPR).

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2009-3070, CVE-2009-3071, CVE-2009-3072, CVE-2009-3074,
  CVE-2009-3075)

  A use-after-free flaw was found in Firefox. An attacker could use this flaw
  to crash Firefox or, potentially, execute arbitrary code with the
  privileges of the user running Firefox. (CVE-2009-3077)

  A flaw was found in the way Firefox handles malformed JavaScript. A website
  with an object containing malicious JavaScript could execute that
  JavaScript with the privileges of the user running Firefox. (CVE-2009-3079)

  Descriptions in the dialogs when adding and removing PKCS #11 modules were
  not informative. An attacker able to trick a user into installing a
  malicious PKCS #11 module could use this flaw to install their own
  Certificate Authority certificates on a user\'s machine, making it possible
  to trick the user into believing they are viewing a trusted site or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2009-3076)

  A flaw was found in the way Firefox displays the address bar when
  window.open() is called in a certain way. An attacker could use this flaw
  to conceal a malicious URL, possibly tricking a user into believing they
  are viewing a trusted site. (CVE-2009-2654)

  A flaw was found in the way Firefox displays certain Unicode characters. An
  attacker could use this flaw to conceal a malicious URL, possibly tricking
  a user into believing they are viewing a trusted site. (CVE-2009-3078)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.0.14. You can find a link to the Mozilla
  advisories in the References section of this errata.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.14, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1430.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2654", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
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

if ( rpm_check( reference:"firefox-3.0.14-1.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-4.7.5-1.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-devel-4.7.5-1.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.14-1.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.14-1.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.14-1.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.14-1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-4.7.5-1.el4_8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-devel-4.7.5-1.el4_8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.14-1.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-4.7.5-1.el4_8", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-devel-4.7.5-1.el4_8", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.14-1.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-4.7.5-1.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-devel-4.7.5-1.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.14-1.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.14-1.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.14-1.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
