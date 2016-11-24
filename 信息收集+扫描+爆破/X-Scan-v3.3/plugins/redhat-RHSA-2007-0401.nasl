
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25366);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0401: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0401");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird packages that fix several security bugs are now
  available for Red Hat Enterprise Linux 4 and 5.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the way Thunderbird processed certain malformed
  JavaScript code. A web page containing malicious JavaScript code could
  cause Thunderbird to crash or potentially execute arbitrary code
  as the user running Thunderbird. (CVE-2007-2867, CVE-2007-2868)

  Several denial of service flaws were found in the way Thunderbird handled
  certain form and cookie data. A malicious web site that is able to set
  arbitrary form and cookie data could prevent Thunderbird from
  functioning properly. (CVE-2007-1362, CVE-2007-2869)

  A flaw was found in the way Thunderbird processed certain APOP
  authentication requests. By sending certain responses when Thunderbird
  attempted to authenticate against an APOP server, a remote attacker could
  potentially acquire certain portions of a user\'s authentication
  credentials. (CVE-2007-1558)

  A flaw was found in the way Thunderbird displayed certain web content. A
  malicious web page could generate content which could overlay user
  interface elements such as the hostname and security indicators, tricking
  users into thinking they are visiting a different site. (CVE-2007-2871)

  Users of Thunderbird are advised to apply this update, which contains
  Thunderbird version 1.5.0.12 that corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0401.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-1362", "CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868", "CVE-2007-2869", "CVE-2007-2871");
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

if ( rpm_check( reference:"thunderbird-1.5.0.12-0.1.el4", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"thunderbird-1.5.0.12-1.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
