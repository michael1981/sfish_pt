
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41591);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for Tomcat 5 (tomcat5-5955)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch tomcat5-5955");
 script_set_attribute(attribute: "description", value: "Two old but not yet fixed security issues in tomcat5 were
spotted and are fixed by this update:

CVE-2006-3835: Apache Tomcat 5 before 5.5.17 allows remote
attackers to list directories via a semicolon (;) preceding
a filename with a mapped extension, as demonstrated by URLs
ending with /;index.jsp and /;help.do.

Cross-site scripting (XSS) vulnerability in certain
applications using Apache Tomcat allowed remote attackers
to inject arbitrary web script or HTML via crafted
'Accept-Language headers that do not conform to RFC 2616'.

These issues were rated 'low' by the Apache Tomcat team.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch tomcat5-5955");
script_end_attributes();

script_cve_id("CVE-2006-3835");
script_summary(english: "Check for the tomcat5-5955 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"tomcat5-5.0.30-27.35", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.0.30-27.35", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.0.30-27.35", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
