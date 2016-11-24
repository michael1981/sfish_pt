
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17252);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-176: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-176");
 script_set_attribute(attribute: "description", value: '
  Updated firefox packages that fix various bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  A bug was found in the Firefox string handling functions. If a malicious
  website is able to exhaust a system\'s memory, it becomes possible to
  execute arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0255 to this issue.

  A bug was found in the way Firefox handles pop-up windows. It is possible
  for a malicious website to control the content in an unrelated site\'s
  pop-up window. (CAN-2004-1156)

  A bug was found in the way Firefox allows plug-ins to load privileged
  content into a frame. It is possible that a malicious webpage could trick a
  user into clicking in certain places to modify configuration settings or
  execute arbitrary code. (CAN-2005-0232 and CAN-2005-0527).

  A flaw was found in the way Firefox displays international domain names. It
  is possible for an attacker to display a valid URL, tricking the user into
  thinking they are viewing a legitimate webpage when they are not.
  (CAN-2005-0233)

  A bug was found in the way Firefox handles plug-in temporary files. A
  malicious local user could create a symlink to a victims directory, causing
  it to be deleted when the victim exits Firefox. (CAN-2005-0578)

  A bug has been found in one of Firefox\'s UTF-8 converters. It may be
  possible for an attacker to supply a specially crafted UTF-8 string to the
  buggy converter, leading to arbitrary code execution. (CAN-2005-0592)

  A bug was found in the Firefox javascript security manager. If a user drags
  a malicious link to a tab, the javascript security manager is bypassed
  which could result in remote code execution or information disclosure.
  (CAN-2005-0231)

  A bug was found in the way Firefox displays the HTTP authentication prompt.
  When a user is prompted for authentication, the dialog window is displayed
  over the active tab, regardless of the tab that caused the pop-up to appear
  and could trick a user into entering their username and password for a
  trusted site. (CAN-2005-0584)

  A bug was found in the way Firefox displays the save file dialog. It is
  possible for a malicious webserver to spoof the Content-Disposition header,
  tricking the user into thinking they are downloading a different filetype.
  (CAN-2005-0586)

  A bug was found in the way Firefox handles users "down-arrow" through auto
  completed choices. When an autocomplete choice is selected, the information
  is copied into the input control, possibly allowing a malicious web site to
  steal information by tricking a user into arrowing through autocompletion
  choices. (CAN-2005-0589)

  Several bugs were found in the way Firefox displays the secure site icon.
  It is possible that a malicious website could display the secure site icon
  along with incorrect certificate information. (CAN-2005-0593)

  A bug was found in the way Firefox displays the download dialog window. A
  malicious site can obfuscate the content displayed in the source field,
  tricking a user into thinking they are downloading content from a trusted
  source. (CAN-2005-0585)

  A bug was found in the way Firefox handles xsl:include and xsl:import
  directives. It is possible for a malicious website to import XSLT
  stylesheets from a domain behind a firewall, leaking information to an
  attacker. (CAN-2005-0588)

  A bug was found in the way Firefox displays the installation confirmation
  dialog. An attacker could add a long user:pass before the true hostname,
  tricking a user into thinking they were installing content from a trusted
  source. (CAN-2005-0590)

  A bug was found in the way Firefox displays download and security dialogs.
  An attacker could cover up part of a dialog window tricking the user into
  clicking "Allow" or "Open", which could potentially lead to arbitrary code
  execution. (CAN-2005-0591)

  Users of Firefox are advised to upgrade to this updated package which
  contains Firefox version 1.0.1 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-176.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1156", "CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0255", "CVE-2005-0527", "CVE-2005-0578", "CVE-2005-0584", "CVE-2005-0585", "CVE-2005-0586", "CVE-2005-0588", "CVE-2005-0589", "CVE-2005-0590", "CVE-2005-0591", "CVE-2005-0592", "CVE-2005-0593");
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

if ( rpm_check( reference:"firefox-1.0.1-1.4.3", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
