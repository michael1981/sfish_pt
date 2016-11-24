
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19277);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-601: thunderbird");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-601");
 script_set_attribute(attribute: "description", value: '
  Updated thunderbird package that fixes various bugs is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mozilla Thunderbird is a standalone mail and newsgroup client.

  A bug was found in the way Thunderbird handled anonymous functions during
  regular expression string replacement. It is possible for a malicious HTML
  mail to capture a random block of client memory. The Common
  Vulnerabilities and Exposures project has assigned this bug the name
  CAN-2005-0989.

  A bug was found in the way Thunderbird validated several XPInstall related
  JavaScript objects. A malicious HTML mail could pass other objects to the
  XPInstall objects, resulting in the JavaScript interpreter jumping to
  arbitrary locations in memory. (CAN-2005-1159)

  A bug was found in the way the Thunderbird privileged UI code handled DOM
  nodes from the content window. An HTML message could install malicious
  JavaScript code or steal data when a user performs commonplace actions such
  as clicking a link or opening the context menu. (CAN-2005-1160)

  A bug was found in the way Thunderbird executed JavaScript code. JavaScript
  executed from HTML mail should run with a restricted access level,
  preventing dangerous actions. It is possible that a malicious HTML mail
  could execute JavaScript code with elevated privileges, allowing access to
  protected data and functions. (CAN-2005-1532)

  A bug was found in the way Thunderbird executed Javascript in XBL controls.
  It is possible for a malicious HTML mail to leverage this vulnerability to
  execute other JavaScript based attacks even when JavaScript is disabled.
  (CAN-2005-2261)

  A bug was found in the way Thunderbird handled certain Javascript
  functions. It is possible for a malicious HTML mail to crash the client by
  executing malformed Javascript code. (CAN-2005-2265)

  A bug was found in the way Thunderbird handled child frames. It is possible
  for a malicious framed HTML mail to steal sensitive information from its
  parent frame. (CAN-2005-2266)

  A bug was found in the way Thunderbird handled DOM node names. It is
  possible for a malicious HTML mail to overwrite a DOM node name, allowing
  certain privileged chrome actions to execute the malicious JavaScript.
  (CAN-2005-2269)

  A bug was found in the way Thunderbird cloned base objects. It is possible
  for HTML content to navigate up the prototype chain to gain access to
  privileged chrome objects. (CAN-2005-2270)

  Users of Thunderbird are advised to upgrade to this updated package that
  contains Thunderbird version 1.0.6 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-601.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0989", "CVE-2005-1159", "CVE-2005-1160", "CVE-2005-1532", "CVE-2005-2261", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2269", "CVE-2005-2270");
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

if ( rpm_check( reference:"thunderbird-1.0.6-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
