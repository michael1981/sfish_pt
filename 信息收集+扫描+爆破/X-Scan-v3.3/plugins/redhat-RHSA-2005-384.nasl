
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18162);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2005-384: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-384");
 script_set_attribute(attribute: "description", value: '
  Updated Mozilla packages that fix various security bugs are now available.

  This update has been rated as having Important security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  Several bugs were found with the way Mozilla displays the secure site icon.
  It is possible that a malicious website could display the secure site icon
  along with incorrect certificate information. (CAN-2005-0143 CAN-2005-0593)

  A bug was found in the way Mozilla handles synthetic middle click events.
  It is possible for a malicious web page to steal the contents of a victims
  clipboard. (CAN-2005-0146)

  Several bugs were found with the way Mozilla handles temporary files. A
  local user could view sensitive temporary information or delete arbitrary
  files. (CAN-2005-0142 CAN-2005-0578)

  A bug was found in the way Mozilla handles pop-up windows. It is possible
  for a malicious website to control the content in an unrelated site\'s
  pop-up window. (CAN-2004-1156)

  A flaw was found in the way Mozilla displays international domain names. It
  is possible for an attacker to display a valid URL, tricking the user into
  thinking they are viewing a legitimate webpage when they are not.
  (CAN-2005-0233)

  A bug was found in the way Mozilla processes XUL content. If a malicious
  web page can trick a user into dragging an object, it is possible to load
  malicious XUL content. (CAN-2005-0401)

  A bug was found in the way Mozilla handles xsl:include and xsl:import
  directives. It is possible for a malicious website to import XSLT
  stylesheets from a domain behind a firewall, leaking information to an
  attacker. (CAN-2005-0588)

  Several bugs were found in the way Mozilla displays alert dialogs. It is
  possible for a malicious webserver or website to trick a user into thinking
  the dialog window is being generated from a trusted site. (CAN-2005-0586
  CAN-2005-0591 CAN-2005-0585 CAN-2005-0590 CAN-2005-0584)

  A bug was found in the Mozilla javascript security manager. If a user drags
  a malicious link to a tab, the javascript security manager is bypassed,
  which could result in remote code execution or information disclosure.
  (CAN-2005-0231)

  A bug was found in the way Mozilla allows plug-ins to load privileged
  content into a frame. It is possible that a malicious webpage could trick a
  user into clicking in certain places to modify configuration settings or
  execute arbitrary code. (CAN-2005-0232 and CAN-2005-0527)

  A bug was found in the way Mozilla handles anonymous functions during
  regular expression string replacement. It is possible for a malicious web
  page to capture a random block of browser memory. (CAN-2005-0989)

  A bug was found in the way Mozilla displays pop-up windows. If a user
  choses to open a pop-up window whose URL is malicious javascript, the
  script will be executed with elevated privileges. (CAN-2005-1153)

  A bug was found in the way Mozilla installed search plugins. If a user
  chooses to install a search plugin from a malicious site, the new plugin
  could silently overwrite an existing plugin. This could allow the malicious
  plugin to execute arbitrary code and stealm sensitive information.
  (CAN-2005-1156 CAN-2005-1157)

  Several bugs were found in the Mozilla javascript engine. A malicious web
  page could leverage these issues to execute javascript with elevated
  privileges or steal sensitive information. (CAN-2005-1154 CAN-2005-1155
  CAN-2005-1159 CAN-2005-1160)

  Users of Mozilla are advised to upgrade to this updated package which
  contains Mozilla version 1.7.7 to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-384.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-1156", "CVE-2005-0142", "CVE-2005-0143", "CVE-2005-0146", "CVE-2005-0231", "CVE-2005-0232", "CVE-2005-0233", "CVE-2005-0401", "CVE-2005-0527", "CVE-2005-0578", "CVE-2005-0584", "CVE-2005-0585", "CVE-2005-0586", "CVE-2005-0588", "CVE-2005-0590", "CVE-2005-0591", "CVE-2005-0593", "CVE-2005-0989", "CVE-2005-1153", "CVE-2005-1154", "CVE-2005-1155", "CVE-2005-1156", "CVE-2005-1157", "CVE-2005-1159", "CVE-2005-1160");
script_summary(english: "Check for the version of the galeon packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"galeon-1.2.14-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.7-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.7-1.1.3.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
