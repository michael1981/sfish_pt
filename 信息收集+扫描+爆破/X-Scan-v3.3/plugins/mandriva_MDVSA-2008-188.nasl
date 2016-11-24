
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36926);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:188: tomcat5");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:188 (tomcat5).");
 script_set_attribute(attribute: "description", value: "A number of vulnerabilities have been discovered in the Apache
Tomcat server:
The default catalina.policy in the JULI logging component did not
restrict certain permissions for web applications which could allow a
remote attacker to modify logging configuration options and overwrite
arbitrary files (CVE-2007-5342).
A cross-site scripting vulnerability was found in the
HttpServletResponse.sendError() method which could allow a remote
attacker to inject arbitrary web script or HTML via forged HTTP headers
(CVE-2008-1232).
A cross-site scripting vulnerability was found in the host manager
application that could allow a remote attacker to inject arbitrary
web script or HTML via the hostname parameter (CVE-2008-1947).
A traversal vulnerability was found when using a RequestDispatcher in
combination with a servlet or JSP that could allow a remote attacker
to utilize a specially-crafted request parameter to access protected
web resources (CVE-2008-2370).
A traversal vulnerability was found when the 'allowLinking' and
'URIencoding' settings were actived which could allow a remote attacker
to use a UTF-8-encoded request to extend their privileges and obtain
local files accessible to the Tomcat process (CVE-2008-2938).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:188");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-5342", "CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370", "CVE-2008-2938");
script_summary(english: "Check for the version of the tomcat5 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tomcat5-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.23-9.2.10.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-eclipse-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.25-1.2.1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tomcat5-", release:"MDK2008.0")
 || rpm_exists(rpm:"tomcat5-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2007-5342", value:TRUE);
 set_kb_item(name:"CVE-2008-1232", value:TRUE);
 set_kb_item(name:"CVE-2008-1947", value:TRUE);
 set_kb_item(name:"CVE-2008-2370", value:TRUE);
 set_kb_item(name:"CVE-2008-2938", value:TRUE);
}
exit(0, "Host is not affected");
