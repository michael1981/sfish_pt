
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42287);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1530: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1530");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security issues are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox. nspr provides the Netscape
  Portable Runtime (NSPR).

  A flaw was found in the way Firefox handles form history. A malicious web
  page could steal saved form data by synthesizing input events, causing the
  browser to auto-fill form fields (which could then be read by an attacker).
  (CVE-2009-3370)

  A flaw was found in the way Firefox creates temporary file names for
  downloaded files. If a local attacker knows the name of a file Firefox is
  going to download, they can replace the contents of that file with
  arbitrary contents. (CVE-2009-3274)

  A flaw was found in the Firefox Proxy Auto-Configuration (PAC) file
  processor. If Firefox loads a malicious PAC file, it could crash Firefox
  or, potentially, execute arbitrary code with the privileges of the user
  running Firefox. (CVE-2009-3372)

  A heap-based buffer overflow flaw was found in the Firefox GIF image
  processor. A malicious GIF image could crash Firefox or, potentially,
  execute arbitrary code with the privileges of the user running Firefox.
  (CVE-2009-3373)

  A heap-based buffer overflow flaw was found in the Firefox string to
  floating point conversion routines. A web page containing malicious
  JavaScript could crash Firefox or, potentially, execute arbitrary code with
  the privileges of the user running Firefox. (CVE-2009-1563)

  A flaw was found in the way Firefox handles text selection. A malicious
  website may be able to read highlighted text in a different domain (e.g.
  another website the user is viewing), bypassing the same-origin policy.
  (CVE-2009-3375)

  A flaw was found in the way Firefox displays a right-to-left override
  character when downloading a file. In these cases, the name displayed in
  the title bar differs from the name displayed in the dialog body. An
  attacker could use this flaw to trick a user into downloading a file that
  has a file name or extension that differs from what the user expected.
  (CVE-2009-3376)

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2009-3374, CVE-2009-3380, CVE-2009-3382)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 3.0.15. You can find a link to the Mozilla
  advisories in the References section of this errata.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 3.0.15, which corrects these issues. After installing the
  update, Firefox must be restarted for the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1530.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1563", "CVE-2009-3274", "CVE-2009-3370", "CVE-2009-3372", "CVE-2009-3373", "CVE-2009-3374", "CVE-2009-3375", "CVE-2009-3376", "CVE-2009-3380", "CVE-2009-3382");
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

if ( rpm_check( reference:"firefox-3.0.15-3.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-4.7.6-1.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-devel-4.7.6-1.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.15-3.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.15-3.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.15-3.el5_4", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.15-3.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-4.7.6-1.el4_8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-devel-4.7.6-1.el4_8", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.15-3.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-4.7.6-1.el4_8", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-devel-4.7.6-1.el4_8", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-3.0.15-3.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-4.7.6-1.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nspr-devel-4.7.6-1.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-1.9.0.15-3.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-1.9.0.15-3.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xulrunner-devel-unstable-1.9.0.15-3.el5_4", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
