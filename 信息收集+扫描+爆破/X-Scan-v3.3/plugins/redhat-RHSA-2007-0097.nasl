
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25318);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0097: devhelp");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0097");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Flaws were found in the way Firefox executed malformed JavaScript code. A
  malicious web page could cause Firefox to crash or allow arbitrary code
  to be executed as the user running Firefox. (CVE-2007-0775, CVE-2007-0777)

  Cross-site scripting (XSS) flaws were found in Firefox. A malicious web
  page could display misleading information, allowing a user to unknowingly
  divulge sensitive information, such as a password. (CVE-2006-6077,
  CVE-2007-0995, CVE-2007-0996)

  A flaw was found in the way Firefox processed JavaScript contained in
  certain tags. A malicious web page could cause Firefox to execute
  JavaScript code with the privileges of the user running Firefox.
  (CVE-2007-0994)

  A flaw was found in the way Firefox cached web pages on the local disk. A
  malicious web page may have been able to inject arbitrary HTML into a
  browsing session if the user reloaded a targeted site. (CVE-2007-0778)

  Certain web content could overlay Firefox user interface elements such as
  the hostname and security indicators. A malicious web page could trick a
  user into thinking they were visiting a different site. (CVE-2007-0779)

  Two flaws were found in Firefox\'s displaying of blocked popup windows. If a
  user could be convinced to open a blocked popup, it was possible to read
  arbitrary local files, or conduct a cross-site scripting attack against the
  user.
  (CVE-2007-0780, CVE-2007-0800)

  Two buffer overflow flaws were found in the Network Security Services (NSS)
  code for processing the SSLv2 protocol. Connecting to a malicious secure
  web server could cause the execution of arbitrary code as the user running
  Firefox. (CVE-2007-0008, CVE-2007-0009)

  A flaw was found in the way Firefox handled the "location.hostname" value.
  A malicious web page could set domain cookies for an arbitrary site, or
  possibly perform a cross-site scripting attack. (CVE-2007-0981)

  Users of Firefox are advised to upgrade to this erratum package, containing
  Firefox version 1.5.0.10 which is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0097.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996");
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

if ( rpm_check( reference:"devhelp-0.12-10.0.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.12-10.0.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-1.5.0.10-2.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-devel-1.5.0.10-2.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"yelp-2.16.0-14.0.1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
