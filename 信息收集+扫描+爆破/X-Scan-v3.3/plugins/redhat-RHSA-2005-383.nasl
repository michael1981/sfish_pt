
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18109);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-383: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-383");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix various security bugs are now available.

  This update has been rated as having Important security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  Vladimir V. Perepelitsa discovered a bug in the way Firefox handles
  anonymous functions during regular expression string replacement. It is
  possible for a malicious web page to capture a random block of browser
  memory. The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CAN-2005-0989 to this issue.

  Omar Khan discovered a bug in the way Firefox processes the PLUGINSPAGE
  tag. It is possible for a malicious web page to trick a user into pressing
  the "manual install" button for an unknown plugin leading to arbitrary
  javascript code execution. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0752 to this issue.

  Doron Rosenberg discovered a bug in the way Firefox displays pop-up
  windows. If a user choses to open a pop-up window whose URL is malicious
  javascript, the script will be executed with elevated privileges. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-1153 to this issue.

  A bug was found in the way Firefox handles the javascript global scope for
  a window. It is possible for a malicious web page to define a global
  variable known to be used by a different site, allowing malicious code to
  be executed in the context of the site. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-1154 to
  this issue.

  Michael Krax discovered a bug in the way Firefox handles favicon links. A
  malicious web page can programatically define a favicon link tag as
  javascript, executing arbitrary javascript with elevated privileges. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-1155 to this issue.

  Michael Krax discovered a bug in the way Firefox installed search plugins.
  If a user chooses to install a search plugin from a malicious site, the new
  plugin could silently overwrite an existing plugin. This could allow the
  malicious plugin to execute arbitrary code and steal sensitive information.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CAN-2005-1156 and CAN-2005-1157 to these issues.

  Kohei Yoshino discovered a bug in the way Firefox opens links in its
  sidebar. A malicious web page could construct a link in such a way that,
  when clicked on, could execute arbitrary javascript with elevated
  privileges. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-1158 to this issue.

  A bug was found in the way Firefox validated several XPInstall related
  javascript objects. A malicious web page could pass other objects to the
  XPInstall objects, resulting in the javascript interpreter jumping to
  arbitrary locations in memory. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-1159 to this issue.

  A bug was found in the way the Firefox privileged UI code handled DOM nodes
  from the content window. A malicious web page could install malicious
  javascript code or steal data requiring a user to do commonplace actions
  such as clicking a link or opening the context menu. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-1160 to this issue.

  Users of Firefox are advised to upgrade to this updated package which
  contains Firefox version 1.0.3 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-383.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0752", "CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1158", "CVE-2005-1159", "CVE-2005-1160");
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

if ( rpm_check( reference:"firefox-1.0.3-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
