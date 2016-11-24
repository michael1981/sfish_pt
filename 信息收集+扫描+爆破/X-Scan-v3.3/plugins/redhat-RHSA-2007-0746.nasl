
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27834);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0746: httpd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0746");
 script_set_attribute(attribute: "description", value: '
  Updated httpd packages that fix a security issue, fix various bugs, and
  add enhancements, are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  The Apache HTTP Server is a popular and freely-available Web server.

  A flaw was found in the Apache HTTP Server mod_proxy module. On sites where
  a reverse proxy is configured, a remote attacker could send a carefully
  crafted request that would cause the Apache child process handling that
  request to crash. On sites where a forward proxy is configured, an attacker
  could cause a similar crash if a user could be persuaded to visit a
  malicious site using the proxy. This could lead to a denial of service if
  using a threaded Multi-Processing Module. (CVE-2007-3847)

  As well, these updated packages fix the following bugs:

  * Set-Cookie headers with a status code of 3xx are not forwarded to
  clients when the "ProxyErrorOverride" directive is enabled. These
  responses are overridden at the proxy. Only the responses with status
  codes of 4xx and 5xx are overridden in these updated packages.

  * the default "/etc/logrotate.d/httpd" script incorrectly invoked the kill
  command, instead of using the "/sbin/service httpd restart" command. If you
  configured the httpd PID to be in a location other than
  "/var/run/httpd.pid", the httpd logs failed to be rotated. This has been
  resolved in these updated packages.

  * the "ProxyTimeout" directive was not inherited across virtual host
  definitions.

  * the logresolve utility was unable to read lines longer the 1024 bytes.

  This update adds the following enhancements:

  * a new configuration option has been added, "ServerTokens Full-Release",
  which adds the package release to the server version string, which is
  returned in the "Server" response header.

  * a new module has been added, mod_version, which allows configuration
  files to be written containing sections, which are evaluated only if the
  version of httpd used matches a specified condition.

  Users of httpd are advised to upgrade to these updated packages, which
  resolve these issues and add these enhancements.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0746.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3847");
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

if ( rpm_check( reference:"httpd-2.2.3-11.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-devel-2.2.3-11.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"httpd-manual-2.2.3-11.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.2.3-11.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
