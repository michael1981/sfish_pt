
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34057);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0648: tomcat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0648");
 script_set_attribute(attribute: "description", value: '
  Updated tomcat packages that fix several security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Apache Tomcat is a servlet container for the Java Servlet and JavaServer
  Pages (JSP) technologies.

  A cross-site scripting vulnerability was discovered in the
  HttpServletResponse.sendError() method. A remote attacker could inject
  arbitrary web script or HTML via forged HTTP headers. (CVE-2008-1232)

  An additional cross-site scripting vulnerability was discovered in the host
  manager application. A remote attacker could inject arbitrary web script or
  HTML via the hostname parameter. (CVE-2008-1947)

  A traversal vulnerability was discovered when using a RequestDispatcher
  in combination with a servlet or JSP. A remote attacker could utilize a
  specially-crafted request parameter to access protected web resources.
  (CVE-2008-2370)

  An additional traversal vulnerability was discovered when the
  "allowLinking" and "URIencoding" settings were activated. A remote attacker
  could use a UTF-8-encoded request to extend their privileges and obtain
  local files accessible to the Tomcat process. (CVE-2008-2938)

  Users of tomcat should upgrade to these updated packages, which contain
  backported patches to resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0648.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370", "CVE-2008-2938");
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

if ( rpm_check( reference:"tomcat5-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.23-0jpp.7.el5_2.1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
