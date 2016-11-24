
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40342);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1164: tomcat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1164");
 script_set_attribute(attribute: "description", value: '
  Updated tomcat packages that fix several security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Apache Tomcat is a servlet container for the Java Servlet and JavaServer
  Pages (JSP) technologies.

  It was discovered that the Red Hat Security Advisory RHSA-2007:0871 did not
  address all possible flaws in the way Tomcat handles certain characters and
  character sequences in cookie values. A remote attacker could use this flaw
  to obtain sensitive information, such as session IDs, and then use this
  information for session hijacking attacks. (CVE-2007-5333)

  Note: The fix for the CVE-2007-5333 flaw changes the default cookie
  processing behavior: with this update, version 0 cookies that contain
  values that must be quoted to be valid are automatically changed to version
  1 cookies. To reactivate the previous, but insecure behavior, add the
  following entry to the "/etc/tomcat5/catalina.properties" file:

  org.apache.tomcat.util.http.ServerCookie.VERSION_SWITCH=false

  It was discovered that request dispatchers did not properly normalize user
  requests that have trailing query strings, allowing remote attackers to
  send specially-crafted requests that would cause an information leak.
  (CVE-2008-5515)

  A flaw was found in the way the Tomcat AJP (Apache JServ Protocol)
  connector processes AJP connections. An attacker could use this flaw to
  send specially-crafted requests that would cause a temporary denial of
  service. (CVE-2009-0033)

  It was discovered that the error checking methods of certain authentication
  classes did not have sufficient error checking, allowing remote attackers
  to enumerate (via brute force methods) usernames registered with
  applications running on Tomcat when FORM-based authentication was used.
  (CVE-2009-0580)

  A cross-site scripting (XSS) flaw was found in the examples calendar
  application. With some web browsers, remote attackers could use this flaw
  to inject arbitrary web script or HTML via the "time" parameter.
  (CVE-2009-0781)

  It was discovered that web applications containing their own XML parsers
  could replace the XML parser Tomcat uses to parse configuration files. A
  malicious web application running on a Tomcat instance could read or,
  potentially, modify the configuration and XML-based data of other web
  applications deployed on the same Tomcat instance. (CVE-2009-0783)

  Users of Tomcat should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Tomcat must be restarted for
  this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1164.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5333", "CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");
script_summary(english: "Check for the version of the tomcat packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tomcat5-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.23-0jpp.7.el5_3.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.23-0jpp.7.el5_3.2", release:'RHEL5.3.') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
