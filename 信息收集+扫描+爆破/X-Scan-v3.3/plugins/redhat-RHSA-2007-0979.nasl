
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27568);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0979: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0979");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security bugs are now available
  for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Several flaws were found in the way in which Firefox processed certain
  malformed web content. A web page containing malicious content could cause
  Firefox to crash or potentially execute arbitrary code as the user running
  Firefox. (CVE-2007-5338, CVE-2007-5339, CVE-2007-5340)

  Several flaws were found in the way in which Firefox displayed malformed
  web content. A web page containing specially-crafted content could
  potentially trick a user into surrendering sensitive information.
  (CVE-2007-1095, CVE-2007-3844, CVE-2007-3511, CVE-2007-5334)

  A flaw was found in the Firefox sftp protocol handler. A malicious web page
  could access data from a remote sftp site, possibly stealing sensitive user
  data. (CVE-2007-5337)

  A request-splitting flaw was found in the way in which Firefox generates a
  digest authentication request. If a user opened a specially-crafted URL, it
  was possible to perform cross-site scripting attacks, web cache poisoning,
  or other, similar exploits. (CVE-2007-2292)

  All users of Firefox are advised to upgrade to these updated packages,
  which contain backported patches that correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0979.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1095", "CVE-2007-2292", "CVE-2007-3511", "CVE-2007-3844", "CVE-2007-5334", "CVE-2007-5337", "CVE-2007-5338", "CVE-2007-5339", "CVE-2007-5340");
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

if ( rpm_check( reference:"firefox-1.5.0.12-6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-devel-1.5.0.12-6.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"firefox-1.5.0.12-0.7.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
