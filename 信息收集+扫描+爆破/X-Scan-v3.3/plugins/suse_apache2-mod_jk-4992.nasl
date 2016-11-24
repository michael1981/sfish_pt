
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31319);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  tomcat security update (apache2-mod_jk-4992)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch apache2-mod_jk-4992");
 script_set_attribute(attribute: "description", value: "Fixed various issues in tomcat:
 - CVE-2006-7196: Cross-site scripting (XSS) vulnerability
   in example JSP applications
 - CVE-2007-3382: Handling of cookies containing a '
   character
 - CVE-2007-3385: Handling of \' in cookies
 - CVE-2007-5641: tomcat path traversal / information leak
 - CVE-2007-1860: directory traversal
 - CVE-2008-0128: tomcat https information disclosure
 - CVE-2005-2090: tomcat HTTP Request Smuggling
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch apache2-mod_jk-4992");
script_end_attributes();

script_cve_id("CVE-2006-7196", "CVE-2007-3382", "CVE-2007-3385", "CVE-2007-5641", "CVE-2007-1860", "CVE-2008-0128", "CVE-2005-2090");
script_summary(english: "Check for the apache2-mod_jk-4992 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apache2-mod_jk-4.1.30-13.4", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-5.0.30-60", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.0.30-60", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.0.30-60", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
