
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25365);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0400: devhelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0400");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Several flaws were found in the way Firefox processed certain malformed
  JavaScript code. A web page containing malicious JavaScript code could
  cause Firefox to crash or potentially execute arbitrary code as the user
  running Firefox. (CVE-2007-2867, CVE-2007-2868)

  A flaw was found in the way Firefox handled certain FTP PASV commands. A
  malicious FTP server could use this flaw to perform a rudimentary
  port-scan of machines behind a user\'s firewall. (CVE-2007-1562)

  Several denial of service flaws were found in the way Firefox handled
  certain form and cookie data. A malicious web site that is able to set
  arbitrary form and cookie data could prevent Firefox from
  functioning properly. (CVE-2007-1362, CVE-2007-2869)

  A flaw was found in the way Firefox handled the addEventListener
  JavaScript method. A malicious web site could use this method to access or
  modify sensitive data from another web site. (CVE-2007-2870)

  A flaw was found in the way Firefox displayed certain web content. A
  malicious web page could generate content that would overlay user
  interface elements such as the hostname and security indicators, tricking
  users into thinking they are visiting a different site. (CVE-2007-2871)

  Users of Firefox are advised to upgrade to these erratum packages, which
  contain Firefox version 1.5.0.12 that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0400.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1362", "CVE-2007-1562", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2870", "CVE-2007-2871");
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

if ( rpm_check( reference:"devhelp-0.12-11.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.12-11.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-1.5.0.12-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-devel-1.5.0.12-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"yelp-2.16.0-15.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-1.5.0.12-0.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
