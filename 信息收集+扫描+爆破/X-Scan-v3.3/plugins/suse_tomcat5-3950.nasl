
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27471);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  tomcat: Securityupdate to fix directory traversal (tomcat5-3950)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch tomcat5-3950");
 script_set_attribute(attribute: "description", value: "Certain characters of the URL were not properly filtered.
This allowed directory reverse traversal attacks to access
the web-root of tomcat. (CVE-2007-0450)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch tomcat5-3950");
script_end_attributes();

script_cve_id("CVE-2007-0450");
script_summary(english: "Check for the tomcat5-3950 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"tomcat5-5.0.30-57", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.0.30-57", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.0.30-57", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
