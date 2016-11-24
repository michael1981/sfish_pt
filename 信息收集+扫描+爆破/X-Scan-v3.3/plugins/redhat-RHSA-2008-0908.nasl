
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34330);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0908: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0908");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird packages that fix several security issues are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed HTML mail content.
  An HTML mail message containing malicious content could cause Thunderbird
  to crash or, potentially, execute arbitrary code as the user running
  Thunderbird. (CVE-2008-0016, CVE-2008-4058, CVE-2008-4059, CVE-2008-4060,
  CVE-2008-4061, CVE-2008-4062)

  Several flaws were found in the way malformed HTML mail content was
  displayed. An HTML mail message containing specially crafted content could
  potentially trick a Thunderbird user into surrendering sensitive
  information. (CVE-2008-3835, CVE-2008-4067, CVE-2008-4068)

  A flaw was found in Thunderbird that caused certain characters to be
  stripped from JavaScript code. This flaw could allow malicious JavaScript
  to bypass or evade script filters. (CVE-2008-4065, CVE-2008-4066)

  Note: JavaScript support is disabled by default in Thunderbird; the above
  issue is not exploitable unless JavaScript is enabled.

  A heap based buffer overflow flaw was found in the handling of cancelled
  newsgroup messages. If the user cancels a specially crafted newsgroup
  message it could cause Thunderbird to crash or, potentially, execute
  arbitrary code as the user running Thunderbird. (CVE-2008-4070)

  All Thunderbird users should upgrade to these updated packages, which
  resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0908.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070");
script_summary(english: "Check for the version of the thunderbird packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"thunderbird-1.5.0.12-16.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"thunderbird-2.0.0.17-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
