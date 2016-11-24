
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41198);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE9 Security Update:  Security update for Tomcat (12078)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE9 system is missing the security patch 12078");
 script_set_attribute(attribute: "description", value: 'Fixed various issues in tomcat:
* CVE-2007-1860: mod_jk directory traversal
* CVE-2007-3382: Handling of cookies containing a \'
character
* CVE-2007-3385: Handling of \\" in cookies
* CVE-2007-5641: tomcat path traversal / information leak
* CVE-2005-2090: tomcat HTTP Request Smuggling
* CVE-2008-0128: tomcat https information disclosure
');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch 12078");
script_end_attributes();

script_cve_id("CVE-2005-2090","CVE-2007-1860","CVE-2007-3382","CVE-2007-3385","CVE-2007-5641","CVE-2008-0128");
script_summary(english: "Check for the security advisory #12078");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"apache-jakarta-tomcat-connectors-5.0.19-29.11", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"apache2-jakarta-tomcat-connectors-5.0.19-29.11", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"jakarta-tomcat-5.0.19-29.11", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"jakarta-tomcat-doc-5.0.19-29.11", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"jakarta-tomcat-examples-5.0.19-29.11", release:"SUSE9", cpu: "i586") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
