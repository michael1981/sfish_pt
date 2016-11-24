
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19837);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-789: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-789");
 script_set_attribute(attribute: "description", value: '
  Updated mozilla packages that fix several security bugs are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  A bug was found in the way Mozilla processes XBM image files. If a user
  views a specially crafted XBM file, it becomes possible to execute
  arbitrary code as the user running Mozilla. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-2701 to
  this issue.

  A bug was found in the way Mozilla processes certain Unicode
  sequences. It may be possible to execute arbitrary code as the user running
  Mozilla, if the user views a specially crafted Unicode sequence.
  (CAN-2005-2702)

  A bug was found in the way Mozilla makes XMLHttp requests. It is possible
  that a malicious web page could leverage this flaw to exploit other proxy
  or server flaws from the victim\'s machine. It is also possible that this
  flaw could be leveraged to send XMLHttp requests to hosts other than the
  originator; the default behavior of the browser is to disallow this.
  (CAN-2005-2703)

  A bug was found in the way Mozilla implemented its XBL interface. It may be
  possible for a malicious web page to create an XBL binding in a way
  that would allow arbitrary JavaScript execution with chrome permissions.
  Please note that in Mozilla 1.7.10 this issue is not directly exploitable
  and would need to leverage other unknown exploits. (CAN-2005-2704)

  An integer overflow bug was found in Mozilla\'s JavaScript engine. Under
  favorable conditions, it may be possible for a malicious web page to
  execute arbitrary code as the user running Mozilla. (CAN-2005-2705)

  A bug was found in the way Mozilla displays about: pages. It is possible
  for a malicious web page to open an about: page, such as about:mozilla, in
  such a way that it becomes possible to execute JavaScript with chrome
  privileges. (CAN-2005-2706)

  A bug was found in the way Mozilla opens new windows. It is possible for a
  malicious web site to construct a new window without any user interface
  components, such as the address bar and the status bar. This window could
  then be used to mislead the user for malicious purposes. (CAN-2005-2707)

  Users of Mozilla are advised to upgrade to this updated package that
  contains Mozilla version 1.7.12 and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-789.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-3089");
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

if ( rpm_check( reference:"galeon-1.2.14-1.2.7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.12-1.1.2.2", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.12-1.1.3.2", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-0.9.2-2.4.7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.9.2-2.4.7", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.12-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
