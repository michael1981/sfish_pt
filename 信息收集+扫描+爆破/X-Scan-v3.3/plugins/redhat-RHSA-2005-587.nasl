
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19285);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-587: galeon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-587");
 script_set_attribute(attribute: "description", value: '
  Updated mozilla packages that fix various security issues are now available.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Mozilla is an open source Web browser, advanced email and newsgroup client,
  IRC chat client, and HTML editor.

  A bug was found in the way Mozilla handled synthetic events. It is possible
  that Web content could generate events such as keystrokes or mouse clicks
  that could be used to steal data or execute malicious Javascript code. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-2260 to this issue.

  A bug was found in the way Mozilla executed Javascript in XBL controls. It
  is possible for a malicious webpage to leverage this vulnerability to
  execute other JavaScript based attacks even when JavaScript is disabled.
  (CAN-2005-2261)

  A bug was found in the way Mozilla installed its extensions. If a user can
  be tricked into visiting a malicious webpage, it may be possible to obtain
  sensitive information such as cookies or passwords. (CAN-2005-2263)

  A bug was found in the way Mozilla handled certain Javascript functions. It
  is possible for a malicious webpage to crash the browser by executing
  malformed Javascript code. (CAN-2005-2265)

  A bug was found in the way Mozilla handled multiple frame domains. It is
  possible for a frame as part of a malicious website to inject content into
  a frame that belongs to another domain. This issue was previously fixed as
  CAN-2004-0718 but was accidentally disabled. (CAN-2005-1937)

  A bug was found in the way Mozilla handled child frames. It is possible for
  a malicious framed page to steal sensitive information from its parent
  page. (CAN-2005-2266)

  A bug was found in the way Mozilla opened URLs from media players. If a
  media player opens a URL which is Javascript, the Javascript executes
  with access to the currently open webpage. (CAN-2005-2267)

  A design flaw was found in the way Mozilla displayed alerts and prompts.
  Alerts and prompts were given the generic title [JavaScript Application]
  which prevented a user from knowing which site created them. (CAN-2005-2268)

  A bug was found in the way Mozilla handled DOM node names. It is possible
  for a malicious site to overwrite a DOM node name, allowing certain
  privileged chrome actions to execute the malicious Javascript. (CAN-2005-2269)

  A bug was found in the way Mozilla cloned base objects. It is possible for
  Web content to traverse the prototype chain to gain access to privileged
  chrome objects. (CAN-2005-2270)

  Users of Mozilla are advised to upgrade to these updated packages, which
  contain Mozilla version 1.7.10 and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-587.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1937", "CVE-2005-2114", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2263", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
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

if ( rpm_check( reference:"galeon-1.2.14-1.2.6", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.10-1.1.2.1", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.10-1.1.3.1", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-0.9.2-2.4.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"devhelp-devel-0.9.2-2.4.6", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-chat-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-devel-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-dom-inspector-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-js-debugger-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-mail-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nspr-devel-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mozilla-nss-devel-1.7.10-1.4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
