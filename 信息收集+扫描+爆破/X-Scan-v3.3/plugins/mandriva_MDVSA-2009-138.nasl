
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39486);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDVSA-2009:138: tomcat5");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:138 (tomcat5).");
 script_set_attribute(attribute: "description", value: "Multiple security vulnerabilities has been identified and fixed
in tomcat5:
Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, 6.0.0 through
6.0.18, and possibly earlier versions normalizes the target pathname
before filtering the query string when using the RequestDispatcher
method, which allows remote attackers to bypass intended access
restrictions and conduct directory traversal attacks via .. (dot dot)
sequences and the WEB-INF directory in a Request (CVE-2008-5515).
Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
through 6.0.18, when the Java AJP connector and mod_jk load balancing
are used, allows remote attackers to cause a denial of service
(application outage) via a crafted request with invalid headers,
related to temporary blocking of connectors that have encountered
errors, as demonstrated by an error involving a malformed HTTP Host
header (CVE-2009-0033).
Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and
6.0.0 through 6.0.18, when FORM authentication is used, allows
remote attackers to enumerate valid usernames via requests to
/j_security_check with malformed URL encoding of passwords, related to
improper error checking in the (1) MemoryRealm, (2) DataSourceRealm,
and (3) JDBCRealm authentication realms, as demonstrated by a %
(percent) value for the j_password parameter (CVE-2009-0580).
The calendar application in the examples web application contains an
XSS flaw due to invalid HTML which renders the XSS filtering protection
ineffective (CVE-2009-0781).
Apache Tomcat 4.1.0 through 4.1.39, 5.5.0 through 5.5.27, and 6.0.0
through 6.0.18 permits web applications to replace an XML parser used
for other web applications, which allows local users to read or modify
the (1) web.xml, (2) context.xml, or (3) tld files of arbitrary web
applications via a crafted application that is loaded earlier than
the target application (CVE-2009-0783).
The updated packages have been patched to prevent this. Additionally
Apache Tomcat has been upgraded to the latest 5.5.27 version for
2009.0.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:138");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");
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

if ( rpm_check( reference:"tomcat5-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-eclipse-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-eclipse-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.27-0.3.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-eclipse-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-common-lib-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-eclipse-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jasper-javadoc-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-jsp-2.0-api-javadoc-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-server-lib-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-servlet-2.4-api-javadoc-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.5.27-0.3.0.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"tomcat5-", release:"MDK2009.0")
 || rpm_exists(rpm:"tomcat5-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2008-5515", value:TRUE);
 set_kb_item(name:"CVE-2009-0033", value:TRUE);
 set_kb_item(name:"CVE-2009-0580", value:TRUE);
 set_kb_item(name:"CVE-2009-0781", value:TRUE);
 set_kb_item(name:"CVE-2009-0783", value:TRUE);
}
exit(0, "Host is not affected");
