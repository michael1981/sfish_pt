
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19268);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-586: firefox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-586");
 script_set_attribute(attribute: "description", value: '
  An updated firefox package that fixes various security bugs is now
  available for Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mozilla Firefox is an open source Web browser.

  A bug was found in the way Firefox handled synthetic events. It is possible
  that Web content could generate events such as keystrokes or mouse clicks
  that could be used to steal data or execute malicious JavaScript code. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-2260 to this issue.


  A bug was found in the way Firefox executed Javascript in XBL controls. It
  is possible for a malicious webpage to leverage this vulnerability to
  execute other JavaScript based attacks even when JavaScript is disabled.
  (CAN-2005-2261)

  A bug was found in the way Firefox set an image as the desktop wallpaper.
  If a user chooses the "Set As Wallpaper..." context menu item on a
  specially crafted image, it is possible for an attacker to execute
  arbitrary code on a victim\'s machine. (CAN-2005-2262)

  A bug was found in the way Firefox installed its extensions. If a user can
  be tricked into visiting a malicious webpage, it may be possible to obtain
  sensitive information such as cookies or passwords. (CAN-2005-2263)

  A bug was found in the way Firefox handled the _search target. It is
  possible for a malicious website to inject JavaScript into an already open
  webpage. (CAN-2005-2264)

  A bug was found in the way Firefox handled certain Javascript functions. It
  is possible for a malicious web page to crash the browser by executing
  malformed Javascript code. (CAN-2005-2265)

  A bug was found in the way Firefox handled multiple frame domains. It is
  possible for a frame as part of a malicious web site to inject content into
  a frame that belongs to another domain. This issue was previously fixed as
  CAN-2004-0718 but was accidentally disabled. (CAN-2005-1937)

  A bug was found in the way Firefox handled child frames. It is possible for
  a malicious framed page to steal sensitive information from its parent
  page. (CAN-2005-2266)

  A bug was found in the way Firefox opened URLs from media players. If a
  media player opens a URL that is JavaScript, JavaScript is executed
  with access to the currently open webpage. (CAN-2005-2267)

  A design flaw was found in the way Firefox displayed alerts and prompts.
  Alerts and prompts were given the generic title [JavaScript Application]
  which prevented a user from knowing which site created them.
  (CAN-2005-2268)

  A bug was found in the way Firefox handled DOM node names. It is possible
  for a malicious site to overwrite a DOM node name, allowing certain
  privileged chrome actions to execute the malicious JavaScript.
  (CAN-2005-2269)

  A bug was found in the way Firefox cloned base objects. It is possible for
  Web content to navigate up the prototype chain to gain access to privileged
  chrome objects. (CAN-2005-2270)

  Users of Firefox are advised to upgrade to this updated package that
  contains Firefox version 1.0.6 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-586.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1937", "CVE-2005-2114", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
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

if ( rpm_check( reference:"firefox-1.0.6-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
