
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(21232);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0328: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0328");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix several security bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  [Updated 24 Apr 2006]
  The erratum text has been updated to include CVE-2006-0748, an issue fixed
  by these erratum packages but which was not public at the time of release.
  No changes have been made to the packages.

  Mozilla Firefox is an open source Web browser.

  Several bugs were found in the way Firefox processes malformed javascript.
  A malicious web page could modify the content of a different open web page,
  possibly stealing sensitive information or conducting a cross-site
  scripting attack. (CVE-2006-1731, CVE-2006-1732, CVE-2006-1741)

  Several bugs were found in the way Firefox processes certain javascript
  actions. A malicious web page could execute arbitrary javascript
  instructions with the permissions of "chrome", allowing the page to steal
  sensitive information or install browser malware. (CVE-2006-1727,
  CVE-2006-1728, CVE-2006-1733, CVE-2006-1734, CVE-2006-1735, CVE-2006-1742)

  Several bugs were found in the way Firefox processes malformed web pages.
  A carefully crafted malicious web page could cause the execution of
  arbitrary code as the user running Firefox. (CVE-2006-0748, CVE-2006-0749,
  CVE-2006-1724, CVE-2006-1730, CVE-2006-1737, CVE-2006-1738, CVE-2006-1739,
  CVE-2006-1790)

  A bug was found in the way Firefox displays the secure site icon. If a
  browser is configured to display the non-default secure site modal warning
  dialog, it may be possible to trick a user into believing they are viewing
  a secure site. (CVE-2006-1740)

  A bug was found in the way Firefox allows javascript mutation events on
  "input" form elements. A malicious web page could be created in such a way
  that when a user submits a form, an arbitrary file could be uploaded to the
  attacker. (CVE-2006-1729)

  Users of Firefox are advised to upgrade to these updated packages
  containing Firefox version 1.0.8 which corrects these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0328.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-0748", "CVE-2006-0749", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
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

if ( rpm_check( reference:"firefox-1.0.8-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
