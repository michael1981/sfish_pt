
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29916);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for Geronimo (geronimo-4864)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch geronimo-4864");
 script_set_attribute(attribute: "description", value: "The file 'implict-objects.jsp' displayed some header values
unfiltered. Attackers could exploit that for cross site
scripting (XSS) attacks (CVE-2006-7195).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch geronimo-4864");
script_end_attributes();

script_cve_id("CVE-2006-7195");
script_summary(english: "Check for the geronimo-4864 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"geronimo-1.0-16.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"geronimo-jetty-servlet-container-1.0-16.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"geronimo-tomcat-servlet-container-1.0-16.6", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
