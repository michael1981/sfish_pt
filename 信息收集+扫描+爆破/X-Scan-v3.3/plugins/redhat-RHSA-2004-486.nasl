
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15409);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-486: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-486");
 script_set_attribute(attribute: "description", value: '
  Updated mozilla packages that fix a number of security issues are now
  available.

  Mozilla is an open source Web browser, advanced email and newsgroup
  client, IRC chat client, and HTML editor.

  Jesse Ruderman discovered a cross-domain scripting bug in Mozilla. If
  a user is tricked into dragging a javascript link into another frame or
  page, it becomes possible for an attacker to steal or modify sensitive
  information from that site. Additionally, if a user is tricked into
  dragging two links in sequence to another window (not frame), it is
  possible for the attacker to execute arbitrary commands. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2004-0905 to this issue.

  Gael Delalleau discovered an integer overflow which affects the BMP
  handling code inside Mozilla. An attacker could create a carefully crafted
  BMP file in such a way that it would cause Mozilla to crash or execute
  arbitrary code when the image is viewed. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2004-0904 to
  this issue.

  Georgi Guninski discovered a stack-based buffer overflow in the vCard
  display routines. An attacker could create a carefully crafted vCard file
  in such a way that it would cause Mozilla to crash or execute arbitrary
  code when viewed. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0903 to this issue.

  Wladimir Palant discovered a flaw in the way javascript interacts with
  the clipboard. It is possible that an attacker could use malicious
  javascript code to steal sensitive data which has been copied into the
  clipboard. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0908 to this issue.

  Georgi Guninski discovered a heap based buffer overflow in the "Send
  Page" feature. It is possible that an attacker could construct a link in
  such a way that a user attempting to forward it could result in a crash or
  arbitrary code execution. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2004-0902 to this issue.

  Users of Mozilla should update to these updated packages, which contain
  backported patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-486.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0902", "CVE-2004-0903", "CVE-2004-0904", "CVE-2004-0905", "CVE-2004-0908");
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

if ( rpm_check( reference:"galeon-1.2.13-5.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.4.3-3.0.4", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
