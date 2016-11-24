
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25724);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0569: tomcat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0569");
 script_set_attribute(attribute: "description", value: '
  Updated tomcat packages that fix two security issues and a packaging bug
  are now available for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Tomcat is a servlet container for Java Servlet and JavaServer Pages (JSP)
  technologies.

  Some JSPs within the \'examples\' web application did not escape user
  provided data. If the JSP examples were accessible, this flaw could allow a
  remote attacker to perform cross-site scripting attacks (CVE-2007-2449).

  Note: it is recommended the \'examples\' web application not be installed on
  a production system.

  The Manager and Host Manager web applications did not escape user provided
  data. If a user is logged in to the Manager or Host Manager web
  application, an attacker could perform a cross-site scripting attack
  (CVE-2007-2450).

  Users of Tomcat should update to these erratum packages, which contain
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0569.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-2449", "CVE-2007-2450");
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

if ( rpm_check( reference:"tomcat5-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.23-0jpp.1.0.4.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
