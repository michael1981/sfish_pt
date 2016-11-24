
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(17624);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-323: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-323");
 script_set_attribute(attribute: "description", value: '
  Updated mozilla packages that fix various bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  A buffer overflow bug was found in the way Mozilla processes GIF images. It
  is possible for an attacker to create a specially crafted GIF image, which
  when viewed by a victim will execute arbitrary code as the victim. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-0399 to this issue.

  A bug was found in the way Mozilla displays dialog windows. It is possible
  that a malicious web page which is being displayed in a background tab
  could present the user with a dialog window appearing to come from the
  active page. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-1380 to this issue.

  A bug was found in the way Mozilla allowed plug-ins to load privileged
  content into a frame. It is possible that a malicious webpage could trick a
  user into clicking in certain places to modify configuration settings or
  execute arbitrary code. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0232 to this issue.

  A bug was found in the way Mozilla Mail handles cookies when loading
  content over HTTP regardless of the user\'s preference. It is possible that
  a particular user could be tracked through the use of malicious mail
  messages which load content over HTTP. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0149 to
  this issue.

  A bug was found in the way Mozilla responds to proxy auth requests. It is
  possible for a malicious webserver to steal credentials from a victims
  browser by issuing a 407 proxy authentication request. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0147 to this issue.

  A bug was found in the way Mozilla handles certain start tags followed by a
  NULL character. A malicious web page could cause Mozilla to crash when
  viewed by a victim. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-1613 to this issue.

  A bug was found in the way Mozilla sets file permissions when installing
  XPI packages. It is possible for an XPI package to install some files
  world readable or writable, allowing a malicious local user to steal
  information or execute arbitrary code. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0906 to
  this issue.

  A bug was found in the way Mozilla loads links in a new tab which are
  middle clicked. A malicious web page could read local files or modify
  privileged chrom settings. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0141 to this issue.

  A bug was found in the way Mozilla displays the secure site icon. A
  malicious web page can use a view-source URL targetted at a secure page,
  while loading an insecure page, yet the secure site icon shows the previous
  secure state. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0144 to this issue.

  Users of Mozilla are advised to upgrade to this updated package which
  contains Mozilla version 1.4.4 and additional backported patches to correct
  these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-323.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0906", "CVE-2004-1380", "CVE-2004-1613", "CVE-2005-0141", "CVE-2005-0144", "CVE-2005-0147", "CVE-2005-0149", "CVE-2005-0232", "CVE-2005-0399");
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

if ( rpm_check( reference:"galeon-1.2.13-6.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.4-1.2.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.4-1.3.5", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
