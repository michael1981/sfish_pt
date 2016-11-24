
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31448);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2008-0042: tomcat");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2008-0042");
 script_set_attribute(attribute: "description", value: '
  Updated tomcat packages that fix security issues and bugs are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Tomcat is a servlet container for Java Servlet and JavaServer Pages
  technologies.

  A directory traversal vulnerability existed in the Apache Tomcat webdav
  servlet. In some configurations it allowed remote authenticated users to
  read files accessible to the local tomcat process. (CVE-2007-5461)

  The default security policy in the JULI logging component did not restrict
  access permissions to files. This could be misused by untrusted web
  applications to access and write arbitrary files in the context of the
  tomcat process. (CVE-2007-5342)

  Users of Tomcat should update to these errata packages, which contain
  backported patches and are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2008-0042.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5342", "CVE-2007-5461");
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

if ( rpm_check( reference:"tomcat5-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.23-0jpp.3.0.3.el5_1", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
