
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24708);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0079: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0079");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Several flaws were found in the way Firefox processed certain malformed
  JavaScript code. A malicious web page could execute JavaScript code in such
  a way that may result in Firefox crashing or executing arbitrary code as
  the user running Firefox. (CVE-2007-0775, CVE-2007-0777)

  Several cross-site scripting (XSS) flaws were found in the way Firefox
  processed certain malformed web pages. A malicious web page could display
  misleading information which may result in a user unknowingly divulging
  sensitive information such as a password. (CVE-2006-6077, CVE-2007-0995,
  CVE-2007-0996)

  A flaw was found in the way Firefox cached web pages on the local disk. A
  malicious web page may be able to inject arbitrary HTML into a browsing
  session if the user reloads a targeted site. (CVE-2007-0778)

  A flaw was found in the way Firefox displayed certain web content. A
  malicious web page could generate content which could overlay user
  interface elements such as the hostname and security indicators, tricking a
  user into thinking they are visiting a different site. (CVE-2007-0779)

  Two flaws were found in the way Firefox displayed blocked popup windows. If
  a user can be convinced to open a blocked popup, it is possible to read
  arbitrary local files, or conduct an XSS attack against the user.
  (CVE-2007-0780, CVE-2007-0800)

  Two buffer overflow flaws were found in the Network Security Services (NSS)
  code for processing the SSLv2 protocol. Connecting to a malicious secure
  web server could cause the execution of arbitrary code as the user running
  Firefox. (CVE-2007-0008, CVE-2007-0009)

  A flaw was found in the way Firefox handled the "location.hostname" value
  during certain browser domain checks. This flaw could allow a malicious web
  site to set domain cookies for an arbitrary site, or possibly perform an
  XSS attack. (CVE-2007-0981)

  Users of Firefox are advised to upgrade to these erratum packages, which
  contain Firefox version 1.5.0.10 that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0079.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1092");
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

if ( rpm_check( reference:"firefox-1.5.0.10-0.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
