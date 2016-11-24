
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(25329);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0327: jakarta");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0327");
 script_set_attribute(attribute: "description", value: '
  Updated tomcat packages that fix multiple security issues are now available
  for Red Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  Tomcat is a servlet container for Java Servlet and JavaServer Pages
  technologies.

  Tomcat was found to accept multiple content-length headers in a
  request. This could allow attackers to poison a web-cache, bypass web
  application firewall protection, or conduct cross-site scripting attacks.
  (CVE-2005-2090)

  Tomcat permitted various characters as path delimiters. If Tomcat was used
  behind certain proxies and configured to only proxy some contexts, an
  attacker could construct an HTTP request to work around the context
  restriction and potentially access non-proxied content. (CVE-2007-0450)

  The implict-objects.jsp file distributed in the examples webapp displayed a
  number of unfiltered header values. If the JSP examples were accessible,
  this flaw could allow a remote attacker to perform cross-site scripting
  attacks. (CVE-2006-7195)

  Users should upgrade to these erratum packages which contain an update to
  Tomcat that resolves these issues. Updated jakarta-commons-modeler
  packages are also included which correct a bug when used with Tomcat 5.5.23.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0327.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2090", "CVE-2006-7195", "CVE-2007-0450", "CVE-2007-1358");
script_summary(english: "Check for the version of the jakarta packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"jakarta-commons-modeler-1.1-8jpp.1.0.2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"jakarta-commons-modeler-javadoc-1.1-8jpp.1.0.2.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.23-0jpp.1.0.3.el5", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
