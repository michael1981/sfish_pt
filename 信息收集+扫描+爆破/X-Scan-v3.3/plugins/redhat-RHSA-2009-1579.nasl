
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42469);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1579: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1579");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 3 and 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular Web server.

  A flaw was found in the way the TLS/SSL (Transport Layer Security/Secure
  Sockets Layer) protocols handle session renegotiation. A man-in-the-middle
  attacker could use this flaw to prefix arbitrary plain text to a client\'s
  session (for example, an HTTPS connection to a website). This could force
  the server to process an attacker\'s request as if authenticated using the
  victim\'s credentials. This update partially mitigates this flaw for SSL
  sessions to HTTP servers using mod_ssl by rejecting client-requested
  renegotiation. (CVE-2009-3555)

  Note: This update does not fully resolve the issue for HTTPS servers. An
  attack is still possible in configurations that require a server-initiated
  renegotiation. Refer to the following Knowledgebase article for further
  information: http://kbase.redhat.com/faq/docs/DOC-20491

  A NULL pointer dereference flaw was found in the Apache mod_proxy_ftp
  module. A malicious FTP server to which requests are being proxied could
  use this flaw to crash an httpd child process via a malformed reply to the
  EPSV or PASV commands, resulting in a limited denial of service.
  (CVE-2009-3094)

  A second flaw was found in the Apache mod_proxy_ftp module. In a reverse
  proxy configuration, a remote attacker could use this flaw to bypass
  intended access restrictions by creating a carefully-crafted HTTP
  Authorization header, allowing the attacker to send arbitrary commands to
  the FTP server. (CVE-2009-3095)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1579.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
script_summary(english: "Check for the version of the httpd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"httpd-2.2.3-31.el5_4.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.2.3-31.el5_4.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.3-31.el5_4.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.3-31.el5_4.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-2.0.46-77.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-77.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-77.ent", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-2.2.3-31.el5_4.2", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.2.3-31.el5_4.2", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.3-31.el5_4.2", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.3-31.el5_4.2", release:'RHEL5.4.') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
