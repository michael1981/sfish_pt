
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21288);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0330: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0330");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird packages that fix various bugs are now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  [Updated 24 Apr 2006]
  The erratum text has been updated to include the details of additional
  issues that were fixed by these erratum packages but which were not public
  at the time of release. No changes have been made to the packages.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several bugs were found in the way Thunderbird processes malformed
  javascript. A malicious HTML mail message could modify the content of a
  different open HTML mail message, possibly stealing sensitive information
  or conducting a cross-site scripting attack. Please note that JavaScript
  support is disabled by default in Thunderbird. (CVE-2006-1731,
  CVE-2006-1732, CVE-2006-1741)

  Several bugs were found in the way Thunderbird processes certain
  javascript actions. A malicious HTML mail message could execute arbitrary
  javascript instructions with the permissions of \'chrome\', allowing the
  page to steal sensitive information or install browser malware. Please
  note that JavaScript support is disabled by default in Thunderbird.
  (CVE-2006-0292, CVE-2006-0296, CVE-2006-1727, CVE-2006-1728, CVE-2006-1733,
  CVE-2006-1734, CVE-2006-1735, CVE-2006-1742)

  Several bugs were found in the way Thunderbird processes malformed HTML
  mail messages. A carefully crafted malicious HTML mail message could
  cause the execution of arbitrary code as the user running Thunderbird.
  (CVE-2006-0748, CVE-2006-0749, CVE-2006-1724, CVE-2006-1730, CVE-2006-1737,
  CVE-2006-1738, CVE-2006-1739, CVE-2006-1790)

  A bug was found in the way Thunderbird processes certain inline content
  in HTML mail messages. It may be possible for a remote attacker to send a
  carefully crafted mail message to the victim, which will fetch remote
  content, even if Thunderbird is configured not to fetch remote content.
  (CVE-2006-1045)

  A bug was found in the way Thunderbird executes in-line mail forwarding. If
  a user can be tricked into forwarding a maliciously crafted mail message as
  in-line content, it is possible for the message to execute javascript with
  the permissions of "chrome". (CVE-2006-0884)

  Users of Thunderbird are advised to upgrade to these updated packages
  containing Thunderbird version 1.0.8, which is not vulnerable to these
  issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0330.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0292", "CVE-2006-0296", "CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1045", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
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

if ( rpm_check( reference:"thunderbird-1.0.8-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
