
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(23962);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0760: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0760");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird packages that fix several security bugs are now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the way Thunderbird processes certain malformed
  Javascript code. A malicious web page could cause the execution of
  Javascript code in such a way that could cause Thunderbird to crash or
  execute arbitrary code as the user running Thunderbird. JavaScript support
  is disabled by default in Thunderbird; this issue is not exploitable
  without enabling JavaScript. (CVE-2006-6498, CVE-2006-6501, CVE-2006-6502,
  CVE-2006-6503, CVE-2006-6504)

  Several flaws were found in the way Thunderbird renders web pages. A
  malicious web page could cause the browser to crash or possibly execute
  arbitrary code as the user running Thunderbird. (CVE-2006-6497)

  A heap based buffer overflow flaw was found in the way Thunderbird parses
  the Content-Type mail header. A malicious mail message could cause the
  Thunderbird client to crash or possibly execute arbitrary code as the user
  running Thunderbird. (CVE-2006-6505)

  Users of Thunderbird are advised to apply this update, which contains
  Thunderbird version 1.5.0.9 that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0760.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-6497", "CVE-2006-6498", "CVE-2006-6501", "CVE-2006-6502", "CVE-2006-6503", "CVE-2006-6504", "CVE-2006-6505");
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

if ( rpm_check( reference:"thunderbird-1.5.0.9-0.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
