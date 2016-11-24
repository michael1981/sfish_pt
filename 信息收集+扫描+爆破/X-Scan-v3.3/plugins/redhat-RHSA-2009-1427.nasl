
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40901);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1427: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1427");
 script_set_attribute(attribute: "description", value: '
  An updated fetchmail package that fixes multiple security issues is now
  available for Red Hat Enterprise Linux 3, 4, and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Fetchmail is a remote mail retrieval and forwarding utility intended for
  use over on-demand TCP/IP links, such as SLIP and PPP connections.

  It was discovered that fetchmail is affected by the previously published
  "null prefix attack", caused by incorrect handling of NULL characters in
  X.509 certificates. If an attacker is able to get a carefully-crafted
  certificate signed by a trusted Certificate Authority, the attacker could
  use the certificate during a man-in-the-middle attack and potentially
  confuse fetchmail into accepting it by mistake. (CVE-2009-2666)

  A flaw was found in the way fetchmail handles rejections from a remote SMTP
  server when sending warning mail to the postmaster. If fetchmail sent a
  warning mail to the postmaster of an SMTP server and that SMTP server
  rejected it, fetchmail could crash. (CVE-2007-4565)

  A flaw was found in fetchmail. When fetchmail is run in double verbose
  mode ("-v -v"), it could crash upon receiving certain, malformed mail
  messages with long headers. A remote attacker could use this flaw to cause
  a denial of service if fetchmail was also running in daemon mode ("-d").
  (CVE-2008-2711)

  Note: when using SSL-enabled services, it is recommended that the fetchmail
  "--sslcertck" option be used to enforce strict SSL certificate checking.

  All fetchmail users should upgrade to this updated package, which contains
  backported patches to correct these issues. If fetchmail is running in
  daemon mode, it must be restarted for this update to take effect (use the
  "fetchmail --quit" command to stop the fetchmail process).


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1427.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4565", "CVE-2008-2711", "CVE-2009-2666");
script_summary(english: "Check for the version of the fetchmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fetchmail-6.3.6-1.1.el5_3.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.0-3.el3.5", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-6.0.1.el4_8.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-6.0.1.el4_8.1", release:'RHEL4.8.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.3.6-1.1.el5_3.1", release:'RHEL5.4.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
