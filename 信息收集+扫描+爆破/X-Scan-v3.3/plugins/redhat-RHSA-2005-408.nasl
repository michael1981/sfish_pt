
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(18280);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-408: cyrus");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-408");
 script_set_attribute(attribute: "description", value: '
  Updated cyrus-imapd packages that fix several buffer overflow security
  issues are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The cyrus-imapd package contains the core of the Cyrus IMAP server.

  Several buffer overflow bugs were found in cyrus-imapd. It is possible that
  an authenticated malicious user could cause the imap server to crash.
  Additionally, a peer news admin could potentially execute arbitrary code on
  the imap server when news is received using the fetchnews command. The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2005-0546 to this issue.

  Users of cyrus-imapd are advised to upgrade to these updated packages, which
  contain cyrus-imapd version 2.2.12 to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-408.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0546");
script_summary(english: "Check for the version of the cyrus packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cyrus-imapd-2.2.12-3.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-devel-2.2.12-3.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-murder-2.2.12-3.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-nntp-2.2.12-3.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cyrus-imapd-utils-2.2.12-3.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"perl-Cyrus-2.2.12-3.RHEL4.1", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
