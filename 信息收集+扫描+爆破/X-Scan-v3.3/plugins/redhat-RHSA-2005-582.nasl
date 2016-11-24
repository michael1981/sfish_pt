
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(19296);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-582: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-582");
 script_set_attribute(attribute: "description", value: '
  Updated Apache httpd packages to correct two security issues are now
  available for Red Hat Enterprise Linux 3 and 4.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a powerful, full-featured, efficient, and
  freely-available Web server.

  Watchfire reported a flaw that occured when using the Apache server as an
  HTTP proxy. A remote attacker could send an HTTP request with both a
  "Transfer-Encoding: chunked" header and a "Content-Length" header. This
  caused Apache to incorrectly handle and forward the body of the request in
  a way that the receiving server processes it as a separate HTTP request.
  This could allow the bypass of Web application firewall protection or lead
  to cross-site scripting (XSS) attacks. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) assigned the name CAN-2005-2088 to this
  issue.

  Marc Stern reported an off-by-one overflow in the mod_ssl CRL verification
  callback. In order to exploit this issue the Apache server would need to
  be configured to use a malicious certificate revocation list (CRL). The
  Common Vulnerabilities and Exposures project (cve.mitre.org) assigned the
  name CAN-2005-1268 to this issue.

  Users of Apache httpd should update to these errata packages that contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-582.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-1268", "CVE-2005-2088");
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

if ( rpm_check( reference:"httpd-2.0.46-46.2.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.46-46.2.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.46-46.2.ent", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-2.0.52-12.1.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.0.52-12.1.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.0.52-12.1.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-suexec-2.0.52-12.1.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.0.52-12.1.ent", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
