
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40143);
 script_version("$Revision: 1.3 $");
 script_name(english: "SuSE 11.0 Security Update:  tomcat6 (2008-08-21)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for tomcat6");
 script_set_attribute(attribute: "description", value: "This update of tomcat fixes another directory traversal bug
which occurs when allowLinking and UTF-8 are enabled.
(CVE-2008-2938)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for tomcat6");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=417217");
script_end_attributes();

 script_cve_id("CVE-2008-2938");
script_summary(english: "Check for the tomcat6 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"tomcat6-6.0.16-6.4", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"tomcat6-admin-webapps-6.0.16-6.4", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"tomcat6-docs-webapp-6.0.16-6.4", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"tomcat6-javadoc-6.0.16-6.4", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"tomcat6-jsp-2_1-api-6.0.16-6.4", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"tomcat6-lib-6.0.16-6.4", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"tomcat6-servlet-2_5-api-6.0.16-6.4", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"tomcat6-webapps-6.0.16-6.4", release:"SUSE11.0", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
