
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39528);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2009-1125: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1125");
 script_set_attribute(attribute: "description", value: '
  An updated thunderbird package that fixes several security issues is now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed HTML mail content.
  An HTML mail message containing malicious content could cause Thunderbird
  to crash or, potentially, execute arbitrary code as the user running
  Thunderbird. (CVE-2009-1392, CVE-2009-1303, CVE-2009-1305, CVE-2009-1833,
  CVE-2009-1838)

  Several flaws were found in the way malformed HTML mail content was
  processed. An HTML mail message containing malicious content could execute
  arbitrary JavaScript in the context of the mail message, possibly
  presenting misleading data to the user, or stealing sensitive information
  such as login credentials. (CVE-2009-1306, CVE-2009-1307, CVE-2009-1309)

  Note: JavaScript support is disabled by default in Thunderbird. None of the
  above issues are exploitable unless JavaScript is enabled.

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1125.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-1303", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1309", "CVE-2009-1392", "CVE-2009-1833", "CVE-2009-1838");
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

if ( rpm_check( reference:"thunderbird-1.5.0.12-23.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"thunderbird-1.5.0.12-23.el4", release:'RHEL4.8.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
