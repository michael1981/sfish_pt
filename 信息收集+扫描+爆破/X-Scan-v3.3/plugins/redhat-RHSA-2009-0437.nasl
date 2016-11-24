
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36214);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2009-0437: seamonkey");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0437");
 script_set_attribute(attribute: "description", value: '
  Updated seamonkey packages that fix several security issues are now
  available for Red Hat Enterprise Linux 2.1, 3, and 4.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  SeaMonkey is an open source Web browser, email and newsgroup client, IRC
  chat client, and HTML editor.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause SeaMonkey to crash or,
  potentially, execute arbitrary code as the user running SeaMonkey.
  (CVE-2009-1303, CVE-2009-1305)

  Several flaws were found in the way malformed web content was processed. A
  web page containing malicious content could execute arbitrary JavaScript in
  the context of the site, possibly presenting misleading data to a user, or
  stealing sensitive information such as login credentials. (CVE-2009-0652,
  CVE-2009-1306, CVE-2009-1307, CVE-2009-1309, CVE-2009-1312)

  A flaw was found in the way SeaMonkey saved certain web pages to a local
  file. If a user saved the inner frame of a web page containing POST data,
  the POST data could be revealed to the inner frame, possibly surrendering
  sensitive information such as login credentials. (CVE-2009-1311)

  All SeaMonkey users should upgrade to these updated packages, which correct
  these issues. After installing the update, SeaMonkey must be restarted for
  the changes to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0437.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0652", "CVE-2009-1303", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1309", "CVE-2009-1311", "CVE-2009-1312");
script_summary(english: "Check for the version of the seamonkey packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"seamonkey-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-chat-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-devel-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-js-debugger-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-devel-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-devel-1.0.9-0.33.el2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-chat-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-devel-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-js-debugger-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nspr-devel-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-nss-devel-1.0.9-0.37.el3", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-1.0.9-41.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-chat-1.0.9-41.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-devel-1.0.9-41.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.9-41.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-js-debugger-1.0.9-41.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.9-41.el4", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
